#!/usr/bin/env python
import argparse
import socket
import struct
import sys
import time

def dns_check(host):
    """
    Performs a DNS lookup for the given host.
    Returns the IP address if successful, None otherwise.
    """
    try:
        ip_address = socket.gethostbyname(host)
        if args.verbose:
            print(f"DNS lookup for {host}: {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"Error: DNS lookup failed for {host}")
        return None

def checksum(msg):
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

def create_ip_tcp_packet(source_ip, dest_ip, dest_port, ttl):
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
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

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
    tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    # Pseudo header for checksum calculation
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header

    tcp_checksum = checksum(psh)

    # Re-pack TCP header with checksum
    tcp_header = struct.pack('!HHLLBBH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)

    # Final packet
    packet = ip_header + tcp_header

    return packet, source_port

def test_proxy_connection(dest_host, dest_port, proxy_host, proxy_port, timeout):
    """
    Tests the connection to the destination through an HTTP proxy.
    """
    print(f"Testing connection to {dest_host}:{dest_port} through proxy {proxy_host}:{proxy_port}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((proxy_host, proxy_port))

        connect_request = f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\nHost: {dest_host}:{dest_port}\r\n\r\n"

        s.sendall(connect_request.encode())
        
        response = s.recv(1024).decode()
        
        if args.verbose:
            print("Proxy response:")
            print(response)
            
        if "200 OK" in response or "200 Connection established" in response:
            print("Connection through proxy successful.")
        else:
            print("Proxy connection failed.")

    except socket.timeout:
        print("Proxy connection timed out.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        s.close()

def main():
    if sys.platform == "win32":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Error: This script requires administrator privileges to run on Windows.")
            sys.exit(1)

    global args
    parser = argparse.ArgumentParser(description="TCP Traceroute and Proxy Tester")
    parser.add_argument("host", help="The destination host.")
    parser.add_argument("-p", "--port", type=int, default=80, help="The destination port (default: 80).")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="The timeout in seconds (default: 5).")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="The maximum number of hops for traceroute (default: 30).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--proxy", help="HTTP proxy address (e.g., host:port). If provided, performs a connection test through the proxy instead of a traceroute.")
    args = parser.parse_args()

    if args.proxy:
        try:
            proxy_host, proxy_port = args.proxy.split(":")
            proxy_port = int(proxy_port)
            test_proxy_connection(args.host, args.port, proxy_host, proxy_port, args.timeout)
            sys.exit(0)
        except ValueError:
            print("Error: Invalid proxy format. Please use host:port.")
            sys.exit(1)

    dest_ip = dns_check(args.host)
    if not dest_ip:
        sys.exit(1)

    print(f"Tracing route to {args.host} [{dest_ip}] over a maximum of {args.max_hops} hops:")

    source_ip = socket.gethostbyname(socket.gethostname())

    for ttl in range(1, args.max_hops + 1):
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.settimeout(args.timeout)
        try:
            recv_socket.bind(("", 0))
        except OSError as e:
            if "requires elevation" in str(e):
                print("Error: This script requires administrator privileges to run.")
                sys.exit(1)
            raise

        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        packet, source_port = create_ip_tcp_packet(source_ip, dest_ip, args.port, ttl)

        try:
            send_socket.sendto(packet, (dest_ip, args.port))
            start_time = time.time()

            data, addr = recv_socket.recvfrom(1024)
            end_time = time.time()

            icmp_header = data[20:28]
            icmp_type, code, _, _, _ = struct.unpack('bbHHh', icmp_header)

            elapsed_time = (end_time - start_time) * 1000
            
            if args.verbose:
                print(f"ICMP packet received from {addr[0]}: type={icmp_type}, code={code}")

            if icmp_type == 11 and code == 0:
                print(f"{ttl:2d}  {addr[0]:<15}  {elapsed_time:.2f} ms")
            elif icmp_type == 3 and (code in [0, 1, 2, 3]):
                print(f"{ttl:2d}  {addr[0]:<15}  {elapsed_time:.2f} ms (Destination Unreachable)")
                break
            
        except socket.timeout:
            check_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            check_socket.settimeout(0.1)
            try:
                check_socket.connect((dest_ip, args.port))
                end_time = time.time()
                elapsed_time = (end_time - start_time) * 1000
                print(f"{ttl:2d}  {dest_ip:<15}  {elapsed_time:.2f} ms (Destination Reached)")
                check_socket.close()
                break
            except (socket.timeout, ConnectionRefusedError):
                print(f"{ttl:2d}  {'*':<15}")
            finally:
                check_socket.close()

        finally:
            recv_socket.close()
            send_socket.close()

if __name__ == "__main__":
    main()
