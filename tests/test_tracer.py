
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import asyncio
import socket

from pytracer.tracer import Tracer

class TestTracer(unittest.IsolatedAsyncioTestCase):

    @patch('asyncio.get_running_loop')
    @patch('socket.socket')
    async def test_trace(self, mock_socket, mock_get_running_loop):
        # Mocks for loop and sockets
        mock_loop = AsyncMock()
        mock_get_running_loop.return_value = mock_loop
        mock_recv_socket = MagicMock()
        mock_send_socket = MagicMock()
        mock_socket.side_effect = [mock_recv_socket, mock_send_socket]

        # Mock sock_recvfrom to return a fake ICMP packet
        mock_loop.sock_recvfrom.return_value = (b'\x00'*20 + b'\x0b\x00\x00\x00\x00\x00\x00\x00', ('1.2.3.4', 0))

        tracer = Tracer(
            dest_ip="8.8.8.8",
            port=80,
            max_hops=1,
            timeout=1,
            verbose=True,
            source_ip="192.168.1.1"
        )

        await tracer.trace()

        # Verify that sockets were created and used
        self.assertEqual(mock_socket.call_count, 2)
        mock_recv_socket.bind.assert_called()
        mock_loop.sock_sendto.assert_awaited()
        mock_loop.sock_recvfrom.assert_awaited()
        mock_recv_socket.close.assert_called()
        mock_send_socket.close.assert_called()

if __name__ == '__main__':
    unittest.main()
