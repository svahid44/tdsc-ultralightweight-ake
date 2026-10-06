import asyncio
from pathlib import Path

from solana.rpc.async_api import AsyncClient


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "tuc/config/solana.conf"


def load_config(path):
    result = {}

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        key, value = line.split("=", 1)
        result[key] = value

    return result


async def main():
    config = load_config(CONFIG)

    rpc_url = config["RPC_URL"]

    print("Network:", config["NETWORK"])
    print("RPC:", rpc_url)

    async with AsyncClient(rpc_url) as client:
        response = await client.get_version()

    print("Response:", response)
    print("STATUS: SOLANA RPC READY")


if __name__ == "__main__":
    asyncio.run(main())
