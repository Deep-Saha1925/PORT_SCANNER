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