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