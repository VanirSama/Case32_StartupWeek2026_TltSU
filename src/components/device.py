from __future__ import annotations

from src.utils.utils import mac_to_str

from abc import ABC, abstractmethod
from ipaddress import IPv4Address
import os


class Device(ABC):
    """
    Класс-интерфейс для сетевых устройств.

    Attributes:
        TYPE: тип устройства в байтовом представлении: b"0" (дефолтное значение), b"e" (Endpoint - конечная станция), b"R" (Router - марщрутизатор).
        _MAC: MAC-адрес устройства, случайное 48-битное число.
        _IP: IP-адрес устройства, задается классом Environment при добавлении устройства.
        connections: ссылки на экземпляры объектов устройств, соединенных с текущим экземпляром
    """

    TYPE = b"0"
    def __init__(self) -> None:

        self._MAC   = Device.random_mac()
        self._IP    = None

        self.connections: list[Device] = []

    @property
    def mac(self) -> int: return self._MAC

    @property
    def ip(self) -> int: return self._IP

    @mac.setter
    def mac(self, new_mac: int) -> None: self._MAC = int(new_mac)

    @ip.setter
    def ip(self, new_ip: int | IPv4Address) -> None: self._IP = int(new_ip)

    @staticmethod
    def random_mac() -> int: return int.from_bytes(os.urandom(6), byteorder="big")

    def add_connection(self, device: Device) -> None:
        if device not in self.connections:
            self.connections.append(device)

    def remove_connection(self, device: Device) -> None: self.connections.remove(device)

    @abstractmethod
    def send(self, payload: bytes) -> None: ...

    @abstractmethod
    def receive(self, payload: bytes) -> None: ...

    def __str__(self) -> str: return f"Device(type={self.TYPE}, ip={self._IP}, mac={mac_to_str(self._MAC)}, connections={self.connections})"
