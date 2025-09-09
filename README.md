# Python Packet Tracer

A simple command-line tool for performing TCP traceroutes, testing proxy connections, and performing TLS checks.

## Features

*   Performs a TCP-based traceroute to a specified host and port.
*   Tests connectivity to a destination through an HTTP proxy.
*   Performs TLS checks on a target host.
*   Verbose mode for detailed output.

## Usage

### Traceroute

```bash
python -m pytracer.main <host> [options]
```

**Options:**

*   `-p, --port <port>`: The destination port (default: 443).
*   `-t, --timeout <seconds>`: The timeout in seconds (default: 5).
*   `-m, --max-hops <hops>`: The maximum number of hops (default: 30).
*   `-v, --verbose`: Enable verbose output.

**Example:**

```bash
python -m pytracer.main google.com -p 443
```

### Proxy Test

```bash
python -m pytracer.main <host> --proxy <proxy_host>:<proxy_port> [options]
```

**Example:**

```bash
python -m pytracer.main google.com --proxy 127.0.0.1:8080
```

### TLS Check

```bash
python -m pytracer.main <host> --tls-check [options]
```

**Options:**

*   `--tls-versions <versions>`: Comma-separated list of TLS versions to check (e.g., 1.0,1.2,1.3). Default is "1.0,1.1,1.2,1.3".

**Example:**

```bash
python -m pytracer.main google.com --tls-check
```

## Running Tests

To run the test suite, use the following command:

```bash
pytest
```
