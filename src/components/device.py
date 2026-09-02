from __future__ import annotations

from src.utils.utils import mac_to_bytes

from asyncio import Queue, create_task
from dataclasses import dataclass


@dataclass
class NetworkInterface:
    ip: str
    mac: bytes
    link: tuple[Device, str] | None = None


class Device:
    def __init__(self, name: str):
        self.name = name
        self.interfaces: dict[str, NetworkInterface] = {}
        self.inbox = Queue()
        self.running = False

    def add_interface(self, iface: str, ip: str, mac: str):
        self.interfaces[iface] = NetworkInterface(ip=ip, mac=mac_to_bytes(mac))

    def connect(self, my_iface: str, other_device: Device, other_iface: str):
        self.interfaces[my_iface].link = (other_device, other_iface)
        other_device.interfaces[other_iface].link = (self, my_iface)

    async def send_frame(self, frame: bytes, out_iface: str):
        link = self.interfaces[out_iface].link
        if link:
            target_dev, target_iface = link
            await target_dev.inbox.put((target_iface, frame))

    async def run(self):
        self.running = True
        while self.running:
            iface, frame = await self.inbox.get()
            create_task(self.process_frame(iface, frame))

    async def process_frame(self, iface: str, frame: bytes):
        raise NotImplementedError