# Port Scanner (C, cross-platform)

A simple educational TCP connect-scan port scanner that compiles and runs
natively on both Linux and Windows terminals, from one shared C source file.

## How it works

- For each port, it attempts a TCP `connect()`. If the OS completes the
  handshake, the port is **open**.
- The socket is set to **non-blocking** and paired with `select()` so a
  filtered/unresponsive port only costs a fixed timeout (500ms by default)
  instead of blocking for 30+ seconds.
- Ports are split across multiple **threads** (pthreads on Linux, native
  Windows threads on Windows) so a full 1–65535 scan doesn't take forever.
- This is a *connect scan*, the same technique `nmap -sT` uses. It does
  **not** require root/admin privileges (unlike a raw SYN scan).

## Build

### Linux / macOS
```bash
gcc portscanner.c -o portscanner -lpthread
```

### Windows (MinGW-w64)
```bash
x86_64-w64-mingw32-gcc portscanner.c -o portscanner.exe -lws2_32
```

### Windows (MSVC — from a "Developer Command Prompt")
```bash
cl portscanner.c ws2_32.lib
```

## Usage

```
./portscanner <host> <start_port> <end_port> [num_threads]
```

Examples:
```bash
./portscanner 127.0.0.1 1 1024          # scan yourself, default 50 threads
./portscanner scanme.nmap.org 1 1000 100  # nmap's official public test target
./portscanner 192.168.1.1 1 65535 200   # full scan of your router
```

On Windows, run the .exe the same way from `cmd` or PowerShell:
```
portscanner.exe 127.0.0.1 1 1024
```

## Notes / things to try extending

- Add a `-v` flag to print closed/filtered ports too, not just open ones.
- Add banner grabbing: after connect(), `recv()` a few bytes to see if the
  service announces itself (e.g. SSH prints its version string immediately).
- Add a simple `service_name(port)` lookup table (21=FTP, 22=SSH, 80=HTTP...).
- Swap the connect scan for a raw SYN scan (needs raw sockets + admin/root +
  manually crafting IP/TCP headers) — a great next-level project.

## Legal note

Only scan hosts you own or have explicit permission to test
(`scanme.nmap.org` is intentionally provided by the nmap project for this
purpose). Scanning networks without authorization can violate computer
misuse laws in most countries, even for "just learning."