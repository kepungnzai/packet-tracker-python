
import asyncio
import socket

class DNSChecker:
    def __init__(self, verbose=False):
        self.verbose = verbose

    async def check(self, host):
        """
        Performs a DNS lookup for the given host.
        Returns the IP address if successful, None otherwise.
        """
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(host, None)
            ip_address = addr_info[0][4][0]
            if self.verbose:
                print(f"DNS lookup for {host}: {ip_address}")
            return ip_address
        except socket.gaierror:
            print(f"Error: DNS lookup failed for {host}")
            return None
