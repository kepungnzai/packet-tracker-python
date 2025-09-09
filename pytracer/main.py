import asyncio
from .cli import CLI

async def main():
    cli = CLI()
    await cli.run()

if __name__ == "__main__":
    asyncio.run(main())