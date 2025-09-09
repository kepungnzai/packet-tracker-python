import asyncio
import argparse
import sys
import socket
import ssl

from .dns_checker import DNSChecker
from .proxy_tester import ProxyTester
from .tracer import Tracer
from .tls_checker import TLSChecker

class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="TCP Traceroute and Proxy Tester")
        self._setup_arguments()

    def _setup_arguments(self):
        self.parser.add_argument("host", help="The destination host.")
        self.parser.add_argument("-p", "--port", type=int, default=443, help="The destination port (default: 443).")
        self.parser.add_argument("-t", "--timeout", type=int, default=5, help="The timeout in seconds (default: 5).")
        self.parser.add_argument("-m", "--max-hops", type=int, default=30, help="The maximum number of hops for traceroute (default: 30).")
        self.parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
        self.parser.add_argument("--proxy", help="HTTP proxy address (e.g., host:port). If provided, performs a connection test through the proxy instead of a traceroute.")
        self.parser.add_argument("--tls-check", action="store_true", help="Perform a TLS check on the target host.")
        self.parser.add_argument("--tls-versions", help="Comma-separated list of TLS versions to check (e.g., 1.0,1.2,1.3).", default="1.0,1.1,1.2,1.3")

    async def run(self):
        if sys.platform == "win32":
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Error: This script requires administrator privileges to run on Windows.")
                sys.exit(1)

        args = self.parser.parse_args()

        if args.proxy:
            try:
                proxy_host, proxy_port = args.proxy.split(":")
                proxy_port = int(proxy_port)
                proxy_tester = ProxyTester(args.host, args.port, proxy_host, proxy_port, args.timeout, args.verbose)
                await proxy_tester.test()
                sys.exit(0)
            except ValueError:
                print("Error: Invalid proxy format. Please use host:port.")
                sys.exit(1)

        if args.tls_check:
            tls_checker = TLSChecker(args.host, args.port)
            print(f"Performing TLS check on {args.host}:{args.port}")

            # Check TLS versions
            versions_to_check = args.tls_versions.split(',')
            tls_protocols = {
                '1.0': ssl.PROTOCOL_TLSv1,
                '1.1': ssl.PROTOCOL_TLSv1_1,
                '1.2': ssl.PROTOCOL_TLSv1_2,
                '1.3': ssl.PROTOCOL_TLS
            }
            for version in versions_to_check:
                version = version.strip()
                if version in tls_protocols:
                    supported = tls_checker.check_tls_version(tls_protocols[version])
                    print(f"TLS {version}: {'Supported' if supported else 'Not Supported'}")
                else:
                    print(f"Unknown TLS version: {version}")

            # Get supported ciphers
            ciphers = tls_checker.get_supported_ciphers()
            if ciphers:
                print("\nSupported Ciphers:")
                for cipher in ciphers:
                    print(f"  {cipher}")
            else:
                print("\nCould not determine supported ciphers.")

            # Get certificate info
            cert_info = tls_checker.get_certificate_info()
            if cert_info:
                print("\nCertificate Information:")
                for key, value in cert_info.items():
                    print(f"  {key}: {value}")
            else:
                print("\nCould not retrieve certificate information.")

            # Get certificate chain
            cert_chain = tls_checker.get_certificate_chain()
            if cert_chain:
                print("\nCertificate Chain:")
                for i, cert in enumerate(cert_chain):
                    print(f"  Certificate {i}:")
                    print(cert)
            else:
                print("\nCould not retrieve certificate chain.")

            sys.exit(0)

        dns_checker = DNSChecker(args.verbose)
        dest_ip = await dns_checker.check(args.host)
        if not dest_ip:
            sys.exit(1)

        loop = asyncio.get_running_loop()
        addr_infos = await loop.getaddrinfo(socket.gethostname(), None)
        source_ip = [info[4][0] for info in addr_infos if info[0] == socket.AF_INET][0]

        tracer = Tracer(dest_ip, args.port, args.max_hops, args.timeout, args.verbose, source_ip)
        await tracer.trace()