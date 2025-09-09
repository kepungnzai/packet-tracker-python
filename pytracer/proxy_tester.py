import asyncio

class ProxyTester:
    def __init__(self, dest_host, dest_port, proxy_host, proxy_port, timeout, verbose=False):
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.timeout = timeout
        self.verbose = verbose

    async def test(self):
        """
        Tests the connection to the destination through an HTTP proxy.
        """
        print(f"Testing connection to {self.dest_host}:{self.dest_port} through proxy {self.proxy_host}:{self.proxy_port}")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.proxy_host, self.proxy_port),
                timeout=self.timeout
            )

            connect_request = f"CONNECT {self.dest_host}:{self.dest_port} HTTP/1.1\r\nHost: {self.dest_host}:{self.dest_port}\r\n\r\n"
            writer.write(connect_request.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            response = response.decode()

            if self.verbose:
                print("Proxy response:")
                print(response)

            if "200 OK" in response or "200 Connection established" in response:
                print("Connection through proxy successful.")
            else:
                print("Proxy connection failed.")

        except asyncio.TimeoutError:
            print("Proxy connection timed out.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            if 'writer' in locals() and writer:
                writer.close()
                await writer.wait_closed()
