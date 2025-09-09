# Python Packet Tracer

A simple command-line tool for performing TCP traceroutes and testing proxy connections.

## Features

*   Performs a TCP-based traceroute to a specified host and port.
*   Tests connectivity to a destination through an HTTP proxy.
*   Verbose mode for detailed output.

## Usage

### Traceroute

```bash
python -m pytracer.main <host> [options]
```

**Options:**

*   `-p, --port <port>`: The destination port (default: 80).
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

## Running Tests

To run the test suite, use the following command:

```bash
python -m unittest discover tests
```