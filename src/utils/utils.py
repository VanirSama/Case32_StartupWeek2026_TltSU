class SingletonMeta(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


def mac_to_str(mac: int) -> str:
    if mac < 0x0 or mac > 0xFFFFFFFFFFFF: return "XX:XX:XX:XX:XX:XX"

    hex_str = f"{mac:012x}".upper()
    return ":".join(hex_str[i:i + 2] for i in range(0, 12, 2))

