# Python Packet Tracer

A simple command-line tool for performing TCP traceroutes and testing proxy connections.

## Features

*   Performs a TCP-based traceroute to a specified host and port.
*   Tests connectivity to a destination through an HTTP proxy.
*   Verbose mode for detailed output.

## Usage

### Traceroute

```bash
python pytracer.py <host> [options]
```

**Options:**

*   `-p, --port <port>`: The destination port (default: 80).
*   `-t, --timeout <seconds>`: The timeout in seconds (default: 5).
*   `-m, --max-hops <hops>`: The maximum number of hops (default: 30).
*   `-v, --verbose`: Enable verbose output.

**Example:**

```bash
python pytracer.py google.com -p 443
```

### Proxy Test

```bash
python pytracer.py <host> --proxy <proxy_host>:<proxy_port> [options]
```

**Example:**

```bash
python pytracer.py google.com --proxy 127.0.0.1:8080
```
