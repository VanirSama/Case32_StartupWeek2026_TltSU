from __future__ import annotations

from src.components.device import Device
from src.config import Config

from ipaddress import IPv4Address, IPv4Network


class Environment:
    def __init__(self):
        self.cfg = Config()

        self.network            = IPv4Network(self.cfg.NETWORK_CIDR)
        self.available_hosts    = self.network.hosts()

        self.devices: dict[int, Device] = {}

    def get_next_free_ip(self) -> IPv4Address:
        try: return next(self.available_hosts)
        except StopIteration: raise ValueError("No available hosts")


    def add_device(self, device: Device) -> None:
        if not device.ip: device.ip = self.get_next_free_ip()
        if not device.mac: device.mac = Device.random_mac()

        self.devices[device.ip] = device