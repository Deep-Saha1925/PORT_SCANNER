/*
 * portscanner.c
 * A simple, educational cross-platform (Linux/Windows) TCP connect-scan port scanner.
 *
 * Concepts demonstrated:
 *  - BSD sockets (Linux) vs Winsock2 (Windows)
 *  - TCP connect scanning (no raw sockets / no admin privileges needed)
 *  - Non-blocking connect() + select() for fast timeouts
 *  - Multithreading to scan ports in parallel (pthreads vs Windows threads)
 *
 * Compile on Linux:
 *   gcc portscanner.c -o portscanner -lpthread
 *
 * Compile on Windows (MinGW):
 *   x86_64-w64-mingw32-gcc portscanner.c -o portscanner.exe -lws2_32
 *
 * Compile on Windows (MSVC, Developer Command Prompt):
 *   cl portscanner.c ws2_32.lib
 *
 * Usage:
 *   ./portscanner <host> <start_port> <end_port> [num_threads]
 *   ./portscanner scanme.nmap.org 1 1024 50
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2rcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef HANDLE thread_handle_t;
    #define CLOSESOCK closesocket

#else
    #include<sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <pthread.h>
    #include <fcntl.h>
    #include <errno.h>
    typedef pthread_t thread_handle_t;
    typedef int SOCKET;
    #define INVALID_SOCKET (-1)
    #define CLOSESOCK close
#endif

#define DEFAULT_TIMEOUT_MS 500

typedef struct {
    const char *host;
    int start_port;
    int end_port;
    int timeout_ms;
} scan_agrs_t;

// Platform setup
int init_sockets(void){
    #ifdef _WIN32
        WSADATA wsa;
        return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    #else
        return 1;
    #endif
}

void cleanup_sockets(void){
    #ifdef _WIN32
        WSACleanup();
    #endif
}

void set_nonblocking(SOCKET sock) {
    #ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
    #else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    #endif
}

/* ---------- Core scanning logic ---------- */
 
/* Returns 1 if the port is open, 0 otherwise. */

int scan_port(const char *host, int port, int timeout_ms) {

    struct addrinfo hints, *res;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;  /* TCP */ 

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return 0;
    }

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return 0;
    }

    set_nonblocking(sock);

    int result = connect(sock, res->ai_addr, (int)res->ai_addrlen);
    int is_open = 0;

    if(result == 0){
        // connected
        is_open = 1;
    } else {
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_sec = (timeout_ms % 1000) * 1000;

    int sel = select((int)sock + 1, NULL, &write_fds, NULL, &tv);
    if (sel > 0){
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len);
        if(so_error == 0) {
            is_open = 1;
        }

        /* sel == 0 -> timed out (likely filtered by a firewall)
           sel < 0  -> select() error, treat as closed */
    }

    CLOSESOCK(sock);
    freeaddrinfo(res);
    return is_open;
}

// Thread worker

#ifdef _WIN32
DWORD WINAPI scan_worker(LPVOID arg){
    #else
    void *scan_worker(void *arg){
    #endif
        scan_args_t *args = (scan_agrs_t *)arg;
        for(int port = args->start_port; port <= args->end_port; port++){
            if(scan_port(args->host, port, args->timeout_ms)){
                printf("[+] Port %d is OPEN\n", port);
                fflush(stdout);
            }
        }
        free(args);
    #ifdef _WIN32
        return 0;
    #else
        return NULL;
    #endif
    }

    thread_handle_t_start_thread(scan_agrs_t *args){
        thread_handle_t handle;
        #ifdef _WIN32
            handle = CreateThread(NULL, 0, scan_worker, args, 0, NULL);
        #else
            pthread_create(&handle, NULL, scan_worker, args);
        #endif
            return handle;
    }

    void join_thread(thread_handle_t handle){
        #ifdef _WIN32
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
        #else
            pthread_join(handle, NULL);
    }

    int main(int argc, char* argv[]){
        if(argc < 4){
            printf("Usage: %s <host> <start_port> <end_port> [num_threads]\n", argv[0]);
            printf("Example: %s scanme.nmap.org 1 1024 50\n", argv[0]);
            return 1;
        }

        const char *host = argv[1];
        int start_port = atoi(argv[2]);
        int end_port = atoi(argv[3]);
        int num_threads = (argc >= 5) ? atoi(argv[4]) : 50;

        if (start_port < 1 || end_port > 65535 || start_port > end_port) {
            printf("Invalid port range. Must be between 1 and 65535, start <= end.\n");
            return 1;
        }

        if (num_threads < 1) num_threads = 1;
 
        if (!init_sockets()) {
            printf("Failed to initialize sockets.\n");
            return 1;
        }

        int total_ports = end_port - start_port + 1;
        if (num_threads > total_ports) num_threads = total_ports;
    
        printf("Scanning %s, ports %d-%d, using %d threads...\n\n", host, start_port, end_port, num_threads);

        clock_t start_time = clock();
    
        int ports_per_thread = total_ports / num_threads;
        thread_handle_t *threads = malloc(sizeof(thread_handle_t) * num_threads);
        int current_port = start_port;

        for (int i = 0; i < num_threads; i++) {
            scan_args_t *args = malloc(sizeof(scan_args_t));
            args->host = host;
            args->timeout_ms = DEFAULT_TIMEOUT_MS;
            args->start_port = current_port;
    
            if (i == num_threads - 1) {
                args->end_port = end_port; /* last thread absorbs any remainder */
            } else {
                args->end_port = current_port + ports_per_thread - 1;
            }
            current_port = args->end_port + 1;
    
            threads[i] = start_thread(args);
        }

        for (int i = 0; i < num_threads; i++) {
            join_thread(threads[i]);
        }

    }
}
