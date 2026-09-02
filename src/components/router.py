from __future__ import annotations

from src.components.device import Device
from src.proto.proto import NetworkPipeline, ARPPacket, EthFrame
from src.utils.utils import bytes_to_ip, ip_to_bytes, bytes_to_mac, mac_to_str, ip_to_str
from src.exceptions import EthFrameError, IPPacketError, ARPPacketError, UDPPacketError

import ipaddress


class Router(Device):
    def __init__(self, name: str):
        super().__init__(name)
        # ip (int) -> mac (bytes)
        self.arp_table: dict[int, bytes] = {}
        # ip (int) -> list of (ip_packet_bytes, out_iface_str)
        self.pending_packets: dict[int, list[tuple[bytes, str]]] = {}

    async def process_frame(self, iface: str, frame: bytes):
        try:
            eth = NetworkPipeline.decap_eth(frame)
            if eth.ethertype == 0x0806: await self.handle_arp(eth.payload, iface)  # ARP
            elif eth.ethertype == 0x0800: await self.handle_ip(eth.payload, iface)  # IP
        except (EthFrameError, IPPacketError, ARPPacketError, UDPPacketError) as e: raise

    async def handle_arp(self, arp_payload: bytes, iface: str):
        arp = NetworkPipeline.decap_arp(arp_payload)

        sender_ip_int = bytes_to_ip(arp.send_ip)
        sender_mac = arp.send_mac

        self.arp_table[sender_ip_int] = sender_mac
        print(f"[{self.name}] ARP Table updated: {ip_to_str(sender_ip_int)} -> {mac_to_str(bytes_to_mac(sender_mac))}")

        if arp.opcode == 1:
            target_ip_int = bytes_to_ip(arp.tgt_ip)
            my_ip_str = self.interfaces[iface].ip
            my_ip_int = bytes_to_ip(ip_to_bytes(my_ip_str))

            if target_ip_int == my_ip_int:
                print(f"[{self.name}] ARP Request for {ip_to_str(target_ip_int)}. Sending Reply...")

                reply_pkt = ARPPacket(
                    opcode=2,
                    send_mac=self.interfaces[iface].mac,
                    send_ip=ip_to_bytes(my_ip_str),
                    tgt_mac=sender_mac,
                    tgt_ip=arp.send_ip
                )
                reply = NetworkPipeline.encap_arp(reply_pkt)

                eth_frame = EthFrame(
                    src_mac=self.interfaces[iface].mac,
                    dst_mac=sender_mac,
                    ethertype=0x0806,
                    payload=reply
                )
                frame = NetworkPipeline.encap_eth(eth_frame)
                await self.send_frame(frame, iface)

        elif arp.opcode == 2:
            if sender_ip_int in self.pending_packets:
                print(f"[{self.name}] Resolved MAC for {ip_to_str(sender_ip_int)}. Flushing buffered packets...")

                for ip_payload, out_iface in self.pending_packets[sender_ip_int]:
                    eth_frame = EthFrame(
                        src_mac=self.interfaces[out_iface].mac,
                        dst_mac=sender_mac,
                        ethertype=0x0800,
                        payload=ip_payload
                    )
                    frame = NetworkPipeline.encap_eth(eth_frame)
                    await self.send_frame(frame, out_iface)

                del self.pending_packets[sender_ip_int]

    async def handle_ip(self, ip_payload: bytes, in_iface: str):
        ip = NetworkPipeline.decap_ip(ip_payload)

        dst_ip_int = bytes_to_ip(ip.dst_ip)
        src_ip_int = bytes_to_ip(ip.src_ip)

        dst_ip_str = ip_to_str(dst_ip_int)
        src_ip_str = ip_to_str(src_ip_int)

        print(f"[{self.name}] Received IP packet from {src_ip_str} to {dst_ip_str}")

        out_iface = self.find_out_iface(dst_ip_str)
        if not out_iface:
            print(f"[{self.name}] No route to {dst_ip_str}. Dropping.")
            return

        dst_mac = self.arp_table.get(dst_ip_int)
        if dst_mac:
            print(f"[{self.name}] Routing packet to {dst_ip_str} via {out_iface}")

            eth_frame = EthFrame(
                src_mac=self.interfaces[out_iface].mac,
                dst_mac=dst_mac,
                ethertype=0x0800,
                payload=ip_payload
            )
            frame = NetworkPipeline.encap_eth(eth_frame)
            await self.send_frame(frame, out_iface)
        else:
            print(f"[{self.name}] No MAC for {dst_ip_str}. Buffering packet and sending ARP Request...")
            self.pending_packets.setdefault(dst_ip_int, []).append((ip_payload, out_iface))
            await self.send_arp_request(dst_ip_str, out_iface)

    async def send_arp_request(self, target_ip: str, out_iface: str):
        my_mac = self.interfaces[out_iface].mac
        my_ip_str = self.interfaces[out_iface].ip

        arp_req_pkt = ARPPacket(
            opcode=1,
            send_mac=my_mac,
            send_ip=ip_to_bytes(my_ip_str),
            tgt_mac=b'\x00\x00\x00\x00\x00\x00',
            tgt_ip=ip_to_bytes(target_ip)
        )
        arp_req = NetworkPipeline.encap_arp(arp_req_pkt)

        eth_frame = EthFrame(
            src_mac=my_mac,
            dst_mac=b'\xff\xff\xff\xff\xff\xff',
            ethertype=0x0806,
            payload=arp_req
        )
        frame = NetworkPipeline.encap_eth(eth_frame)
        await self.send_frame(frame, out_iface)

    def find_out_iface(self, ip: str):
        for iface_name, data in self.interfaces.items():
            if data.link:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(f"{data.ip}/24", strict=False):
                    return iface_name
        return list(self.interfaces.keys())[0]