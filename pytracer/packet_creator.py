
import socket
import struct

class PacketCreator:
    def __init__(self, source_ip, dest_ip, dest_port):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.dest_port = dest_port

    def checksum(self, msg):
        """
        Calculates the checksum for the given message.
        """
        s = 0
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        if len(msg) % 2 != 0:
            msg += b'\0'
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i+1]
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        return ~s & 0xffff

    def create_ip_tcp_packet(self, ttl):
        # IP header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 40  # IP header + TCP header
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = ttl
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  # Kernel will fill in the correct checksum
        ip_saddr = socket.inet_aton(self.source_ip)
        ip_daddr = socket.inet_aton(self.dest_ip)

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        # IP header
        ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

        # TCP header fields
        source_port = 12345
        seq = 0
        ack_seq = 0
        doff = 5  # 4-bit field, size of tcp header in 32-bit words
        # TCP flags
        fin = 0
        syn = 1
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0

        offset_res = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

        # TCP header
        tcp_header = struct.pack('!HHLLBBHHH', source_port, self.dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

        # Pseudo header for checksum calculation
        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header

        tcp_checksum = self.checksum(psh)

        # Re-pack TCP header with checksum
        tcp_header = struct.pack('!HHLLBBH', source_port, self.dest_port, seq, ack_seq, offset_res, tcp_flags, window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)

        # Final packet
        packet = ip_header + tcp_header

        return packet, source_port
