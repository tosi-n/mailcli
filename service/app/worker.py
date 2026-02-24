from __future__ import annotations

# mailcli worker is optional in v1.
# This entrypoint exists so the repo matches the tool-service pattern and can
# adopt Choreo for heavy mailbox fetch/reprocessing later.

import asyncio


async def main() -> None:
    await asyncio.sleep(0.1)


if __name__ == "__main__":
    asyncio.run(main())

