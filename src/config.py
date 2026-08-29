from src.utils.utils import SingletonMeta

from pathlib import Path
from tomllib import load


class Config(metaclass=SingletonMeta):
    DEFAULT_CONFIG = Path(__file__).parent.parent / "config.toml"

    def __init__(self):
        self.cfg = {}

        self.load()

    def load(self):
        self.cfg = load(open(self.DEFAULT_CONFIG, mode="rb"))

        self.NETWORK_CIDR           = self.cfg.get("network_cidr", "192.168.1.0/24")

        self.BANDWIDTH              = self.cfg.get("bandwidth", 100)
        self.TTL                    = self.cfg.get("ttl", 60)

        self.ROUTER_TTL             = self.cfg.get("router_ttl", 300)