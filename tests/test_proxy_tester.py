import unittest
from unittest.mock import patch, AsyncMock
import asyncio

from pytracer.proxy_tester import ProxyTester

class TestProxyTester(unittest.IsolatedAsyncioTestCase):

    @patch('asyncio.open_connection')
    async def test_test_success(self, mock_open_connection):
        # Configure the mock to return two AsyncMocks, one for the reader and one for the writer
        mock_reader, mock_writer = AsyncMock(), AsyncMock()
        mock_open_connection.return_value = (mock_reader, mock_writer)
        
        # Set the return value for the reader's read method
        mock_reader.read.return_value = b'HTTP/1.1 200 OK\r\n\r\n'

        # Initialize the proxy tester
        proxy_tester = ProxyTester(
            dest_host="example.com",
            dest_port=80,
            proxy_host="proxy.example.com",
            proxy_port=8080,
            timeout=5,
            verbose=True
        )
        
        # Run the test
        await proxy_tester.test()

        # Assert that the expected calls were made
        mock_writer.write.assert_called_once()
        mock_writer.drain.assert_awaited_once()
        mock_reader.read.assert_awaited_once()
        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_awaited_once()

    @patch('asyncio.open_connection', side_effect=asyncio.TimeoutError)
    async def test_test_timeout(self, mock_open_connection):
        # Initialize the proxy tester
        proxy_tester = ProxyTester(
            dest_host="example.com",
            dest_port=80,
            proxy_host="proxy.example.com",
            proxy_port=8080,
            timeout=5
        )
        
        # Run the test and expect it to handle the timeout gracefully
        await proxy_tester.test()
        
        # Verify that open_connection was called
        mock_open_connection.assert_awaited_once()

if __name__ == '__main__':
    unittest.main()