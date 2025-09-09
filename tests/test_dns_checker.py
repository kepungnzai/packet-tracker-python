
import unittest
from unittest.mock import patch, AsyncMock
import asyncio
import socket

from pytracer.dns_checker import DNSChecker

class TestDNSChecker(unittest.IsolatedAsyncioTestCase):

    @patch('asyncio.get_running_loop')
    async def test_check_success(self, mock_get_running_loop):
        # Create a mock for the loop object
        mock_loop = AsyncMock()
        # Configure the mock for getaddrinfo to return a sample address
        mock_loop.getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 0))
        ]
        # Have get_running_loop return our mock loop
        mock_get_running_loop.return_value = mock_loop

        # Instantiate the checker and perform the check
        dns_checker = DNSChecker(verbose=True)
        ip = await dns_checker.check("example.com")
        
        # Assert that the returned IP is as expected
        self.assertEqual(ip, "192.168.1.1")

    @patch('asyncio.get_running_loop')
    async def test_check_fail(self, mock_get_running_loop):
        # Create a mock for the loop object
        mock_loop = AsyncMock()
        # Configure getaddrinfo to raise a gaierror, simulating a failed lookup
        mock_loop.getaddrinfo.side_effect = socket.gaierror
        # Have get_running_loop return our mock loop
        mock_get_running_loop.return_value = mock_loop

        # Instantiate the checker and perform the check
        dns_checker = DNSChecker()
        ip = await dns_checker.check("nonexistent.com")
        
        # Assert that the IP is None, as the lookup failed
        self.assertIsNone(ip)

if __name__ == '__main__':
    unittest.main()
