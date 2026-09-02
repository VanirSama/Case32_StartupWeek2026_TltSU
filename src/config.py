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
        self.TTL                    = self.cfg.get("ttl", 60)
        self.UDP_PORT               = self.cfg.get("udp_port", 23)


config = Config()