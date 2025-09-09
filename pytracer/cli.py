
import asyncio
import argparse
import sys
import socket

from .dns_checker import DNSChecker
from .proxy_tester import ProxyTester
from .tracer import Tracer

class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="TCP Traceroute and Proxy Tester")
        self._setup_arguments()

    def _setup_arguments(self):
        self.parser.add_argument("host", help="The destination host.")
        self.parser.add_argument("-p", "--port", type=int, default=80, help="The destination port (default: 80).")
        self.parser.add_argument("-t", "--timeout", type=int, default=5, help="The timeout in seconds (default: 5).")
        self.parser.add_argument("-m", "--max-hops", type=int, default=30, help="The maximum number of hops for traceroute (default: 30).")
        self.parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
        self.parser.add_argument("--proxy", help="HTTP proxy address (e.g., host:port). If provided, performs a connection test through the proxy instead of a traceroute.")

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

        dns_checker = DNSChecker(args.verbose)
        dest_ip = await dns_checker.check(args.host)
        if not dest_ip:
            sys.exit(1)

        loop = asyncio.get_running_loop()
        addr_infos = await loop.getaddrinfo(socket.gethostname(), None)
        source_ip = [info[4][0] for info in addr_infos if info[0] == socket.AF_INET][0]

        tracer = Tracer(dest_ip, args.port, args.max_hops, args.timeout, args.verbose, source_ip)
        await tracer.trace()
