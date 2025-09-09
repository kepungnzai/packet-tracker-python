
import ssl
import socket
from typing import List, Dict, Any

class TLSChecker:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def check_tls_version(self, tls_version: int) -> bool:
        """Checks if a specific TLS version is supported by the server."""
        try:
            context = ssl.SSLContext(tls_version)
            with socket.create_connection((self.host, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    return True
        except (ssl.SSLError, ConnectionRefusedError, socket.timeout):
            return False

    def get_supported_ciphers(self) -> List[str]:
        """Gets the list of supported ciphers from the server."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    ciphers = ssock.shared_ciphers()
                    if ciphers:
                        return [cipher[0] for cipher in ciphers]
                    return []
        except (ssl.SSLError, ConnectionRefusedError, socket.timeout):
            return []

    def get_certificate_info(self) -> Dict[str, Any]:
        """Gets information about the server's certificate."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except (ssl.SSLError, ConnectionRefusedError, socket.timeout):
            return {}

    def get_certificate_chain(self) -> List[Dict[str, Any]]:
        """Gets the server's certificate chain."""
        try:
            context = ssl.create_default_context()
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            with socket.create_connection((self.host, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    chain = ssock.getpeercert(True)
                    if chain:
                        return [ssl.DER_cert_to_PEM_cert(c) for c in chain if isinstance(c, bytes)]
                    return []
        except (ssl.SSLError, ConnectionRefusedError, socket.timeout):
            return []
