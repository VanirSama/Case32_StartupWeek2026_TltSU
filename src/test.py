from src.components.endpoint import Endpoint
from src.components.router import Router

import asyncio

async def test():
    pc1 = Endpoint("PC1", gateway="10.0.0.1")
    pc2 = Endpoint("PC2", gateway="192.168.1.1")
    router = Router("Router1")

    pc1.add_interface("eth0", "10.0.0.2", "02:00:00:00:00:02")
    router.add_interface("eth0", "10.0.0.1", "02:00:00:00:00:01")
    router.add_interface("eth1", "192.168.1.1", "02:00:00:00:00:11")
    pc2.add_interface("eth0", "192.168.1.2", "02:00:00:00:00:22")

    pc1.connect("eth0", router, "eth0")
    router.connect("eth1", pc2, "eth0")

    devices = [pc1, router, pc2]
    tasks = [asyncio.create_task(dev.run()) for dev in devices]

    await pc1.send_udp_message("192.168.1.2", 8080, "Hello from PC1!")
    await asyncio.sleep(2.0)
    print(f"PC2 received messages: {pc2.received_messages}")

    for dev in devices: dev.running = False
    for task in tasks: task.cancel()


if __name__ == "__main__":
    asyncio.run(test())