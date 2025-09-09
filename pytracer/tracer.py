
import asyncio
import socket
import struct
import time

from .packet_creator import PacketCreator

class Tracer:
    def __init__(self, dest_ip, port, max_hops, timeout, verbose, source_ip):
        self.dest_ip = dest_ip
        self.port = port
        self.max_hops = max_hops
        self.timeout = timeout
        self.verbose = verbose
        self.source_ip = source_ip

    async def trace(self):
        print(f"Tracing route to {self.dest_ip} over a maximum of {self.max_hops} hops:")

        for ttl in range(1, self.max_hops + 1):
            loop = asyncio.get_running_loop()
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_socket.setblocking(False)
            try:
                recv_socket.bind(("", 0))
            except OSError as e:
                if "requires elevation" in str(e):
                    print("Error: This script requires administrator privileges to run.")
                    return
                raise

            send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            send_socket.setblocking(False)

            packet_creator = PacketCreator(self.source_ip, self.dest_ip, self.port)
            packet, source_port = packet_creator.create_ip_tcp_packet(ttl)

            try:
                await loop.sock_sendto(send_socket, packet, (self.dest_ip, self.port))
                start_time = time.time()

                data, addr = await asyncio.wait_for(loop.sock_recvfrom(recv_socket, 1024), timeout=self.timeout)
                end_time = time.time()

                icmp_header = data[20:28]
                icmp_type, code, _, _, _ = struct.unpack('bbHHh', icmp_header)

                elapsed_time = (end_time - start_time) * 1000
                
                if self.verbose:
                    print(f"ICMP packet received from {addr[0]}: type={icmp_type}, code={code}")

                if icmp_type == 11 and code == 0:
                    print(f"{ttl:2d}  {addr[0]:<15}  {elapsed_time:.2f} ms")
                elif icmp_type == 3 and (code in [0, 1, 2, 3]):
                    print(f"{ttl:2d}  {addr[0]:<15}  {elapsed_time:.2f} ms (Destination Unreachable)")
                    break
                
            except asyncio.TimeoutError:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.dest_ip, self.port),
                        timeout=0.1
                    )
                    end_time = time.time()
                    elapsed_time = (end_time - start_time) * 1000
                    print(f"{ttl:2d}  {self.dest_ip:<15}  {elapsed_time:.2f} ms (Destination Reached)")
                    writer.close()
                    await writer.wait_closed()
                    break
                except (asyncio.TimeoutError, ConnectionRefusedError):
                    print(f"{ttl:2d}  {'*':<15}")

            finally:
                recv_socket.close()
                send_socket.close()
