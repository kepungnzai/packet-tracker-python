
import unittest
import socket

from pytracer.packet_creator import PacketCreator

class TestPacketCreator(unittest.TestCase):

    def setUp(self):
        self.source_ip = "192.168.1.1"
        self.dest_ip = "8.8.8.8"
        self.dest_port = 80
        self.packet_creator = PacketCreator(self.source_ip, self.dest_ip, self.dest_port)

    def test_checksum(self):
        # Test with a simple message
        msg = b'hello'
        # The checksum will be calculated and should not be 0
        self.assertNotEqual(self.packet_creator.checksum(msg), 0)

    def test_create_ip_tcp_packet(self):
        ttl = 64
        packet, source_port = self.packet_creator.create_ip_tcp_packet(ttl)
        
        # The packet should not be empty
        self.assertIsNotNone(packet)
        # The packet length should be greater than 0
        self.assertGreater(len(packet), 0)
        # The source port should be an integer
        self.assertIsInstance(source_port, int)

if __name__ == '__main__':
    unittest.main()
