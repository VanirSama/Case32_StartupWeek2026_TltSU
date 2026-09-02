from src.exceptions import EthFrameError, IPPacketError, ARPPacketError, UDPPacketError
from src.config import config

from binascii import crc32
from pydantic import BaseModel, Field, ValidationError
from struct import pack, unpack


class EthFrame(BaseModel):
    src_mac: bytes  = Field(min_length=6, max_length=6)
    dst_mac: bytes  = Field(min_length=6, max_length=6)
    ethertype: int  = 0x0800
    payload: bytes  = Field(max_length=1500)


class IPPacket(BaseModel):
    ip_v: int           = 0x4
    ihl_len: int        = 5
    tos: int            = 0
    id: int             = 1
    flags: int          = 0
    ttl: int            = config.TTL
    proto: int          = Field(default=0x11)
    src_ip: bytes       = Field(min_length=4, max_length=4)
    dst_ip: bytes       = Field(min_length=4, max_length=4)
    payload: bytes      = Field(max_length=65515)


class ARPPacket(BaseModel):
    hardware: int   = 1
    proto_type: int = 0x0800
    hw_len: int     = 6
    proto_len: int  = 4
    opcode: int     = Field(ge=0x0, le=0xFFFF)
    send_mac: bytes = Field(min_length=6, max_length=6)
    send_ip: bytes  = Field(min_length=4, max_length=4)
    tgt_mac: bytes  = Field(min_length=6, max_length=6)
    tgt_ip: bytes   = Field(min_length=4, max_length=4)


class UDPPacket(BaseModel):
    src_port: int   = config.UDP_PORT
    dst_port: int   = config.UDP_PORT
    payload: bytes  = Field(max_length=65515)


class NetworkPipeline:
    @staticmethod
    def _crc_32_checksum(data: bytes) -> bytes: return (crc32(data) & 0xFFFFFFFF).to_bytes(4, byteorder='big')

    @staticmethod
    def _rfc_791_checksum(data: bytes) -> bytes:
        if len(data) % 2 == 1: data += b"\x00"
        total_sum = 0
        for i in range(0, len(data), 2): total_sum += ((data[i] << 8) + data[i + 1])

        while total_sum >> 16: total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)

        return (~total_sum) & 0xFFFF

    @staticmethod
    def encap_eth(frame: EthFrame) -> bytes:
        eth_header = pack("!6s6sH", frame.dst_mac, frame.src_mac, frame.ethertype)
        frame_no_fcs = eth_header + frame.payload
        fcs = NetworkPipeline._crc_32_checksum(frame_no_fcs)
        return frame_no_fcs + fcs

    @staticmethod
    def decap_eth(raw_frame: bytes) -> EthFrame:
        if len(raw_frame) < 18: raise EthFrameError("Invalid Ethernet frame length")
        eth_header = raw_frame[:14]
        dst_mac, src_mac, ethertype = unpack("!6s6sH", eth_header)
        payload = raw_frame[14:-4]
        fcs_recv = raw_frame[-4:]
        fcs_calc = NetworkPipeline._crc_32_checksum(raw_frame[:-4])
        if  fcs_recv != fcs_calc: raise EthFrameError("Ethernet FCS (CRC-32) checksum mismatch")

        try: return EthFrame(src_mac=src_mac, dst_mac=dst_mac, ethertype=ethertype, payload=payload)
        except ValidationError as e: raise EthFrameError("Invalid Ethernet frame model")

    @staticmethod
    def encap_ip(packet: IPPacket) -> bytes:
        version_ihl = (packet.ip_v << 4) | packet.ihl_len
        total_length = 20 + len(packet.payload)
        ip_header_no_cs = pack('!BBHHHBBH4s4s', version_ihl, packet.tos, total_length, packet.id, packet.flags, packet.ttl, packet.proto, 0, packet.src_ip, packet.dst_ip)
        checksum = NetworkPipeline._rfc_791_checksum(ip_header_no_cs)

        ip_header = pack('!BBHHHBBH4s4s', version_ihl, packet.tos, total_length, packet.id, packet.flags, packet.ttl, packet.proto, checksum, packet.src_ip, packet.dst_ip)

        return ip_header + packet.payload

    @staticmethod
    def decap_ip(raw_packet: bytes) -> IPPacket:
        if len(raw_packet) < 20: raise IPPacketError("Invalid IP Packet length")
        header_bytes = raw_packet[:20]
        version_ihl, tos, total_length, ident, flags_offset, ttl, proto, checksum, src_ip, dst_ip = unpack('!BBHHHBBH4s4s', header_bytes)

        version = version_ihl >> 4
        ihl = version_ihl & 0x0F

        if version != 4: raise IPPacketError(f"Unsupported IP version: v{version}. Expected v4")
        if ihl != 5: raise IPPacketError(f"Expected optionless header (IHL=5), received IHL={ihl}")

        if len(raw_packet) < total_length: raise IPPacketError(f"Truncated packet: expected {total_length} bytes, received {len(raw_packet)}")

        if NetworkPipeline._rfc_791_checksum(header_bytes) != 0: raise IPPacketError("Invalid IP header checksum")
        payload_bytes = raw_packet[20:total_length]

        try: return IPPacket(src_ip=src_ip, dst_ip=dst_ip, proto=proto, payload=payload_bytes)
        except ValidationError: raise IPPacketError("Invalid IP packet model")

    @staticmethod
    def encap_arp(packet: ARPPacket) -> bytes:
        arp_header = pack('!HHBBH6s4s6s4s', packet.hardware, packet.proto_type, packet.hw_len, packet.proto_len,
                          packet.opcode, packet.send_mac, packet.send_ip, packet.tgt_mac, packet.tgt_ip)

        return arp_header

    @staticmethod
    def decap_arp(raw_packet: bytes) -> ARPPacket:
        if len(raw_packet) != 28: raise ARPPacketError("Invalid ARP packet length")
        hardware, proto_type, hw_len, proto_len, opcode, send_mac, send_ip, tgt_mac, tgt_ip = unpack('!HHBBH6s4s6s4s', raw_packet)

        try: return ARPPacket(opcode=opcode, send_mac=send_mac, send_ip=send_ip, tgt_mac=tgt_mac, tgt_ip=tgt_ip)
        except ValidationError: raise ARPPacketError("Invalid ARP packet model")

    @staticmethod
    def encap_udp(packet: UDPPacket) -> bytes:
        length = 8 + len(packet.payload)
        udp_header_no_cs = pack('!HHHH', packet.src_port, packet.dst_port, length, 0)
        checksum = NetworkPipeline._rfc_791_checksum(udp_header_no_cs + packet.payload)
        udp_header = pack('!HHHH', packet.src_port, packet.dst_port, length, checksum)

        return udp_header + packet.payload

    @staticmethod
    def decap_udp(raw_packet: bytes) -> UDPPacket:
        if len(raw_packet) < 8: raise UDPPacketError("Invalid UDP segment length")
        src_port, dst_port, length, cs_recv = unpack('!HHHH', raw_packet[:8])
        payload = raw_packet[8:]

        udp_header_no_cs = pack('!HHHH', src_port, dst_port, length, 0)
        cs_calc = NetworkPipeline._rfc_791_checksum(udp_header_no_cs + payload)
        if cs_recv != cs_calc: raise UDPPacketError("UDP checksum mismatch")

        try: return UDPPacket(src_port=src_port, dst_port=dst_port, payload=payload)
        except ValidationError: raise UDPPacketError("Invalid UDP packet model")