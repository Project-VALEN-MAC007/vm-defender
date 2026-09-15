"""Generate offline-only HTTP PCAPs using RFC 5737 documentation addresses."""
from pathlib import Path
import socket
import struct
import time


def checksum(data):
    if len(data) % 2: data += b"\0"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff


def frame(src, dst, sport, dport, seq, ack, flags, payload=b"", ident=1, reverse=False):
    source = socket.inet_aton(src); destination = socket.inet_aton(dst)
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp_sum = checksum(pseudo + tcp + payload)
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, tcp_sum, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), ident,
                     0x4000, 64, 6, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    client_mac = bytes.fromhex("020000000020"); server_mac = bytes.fromhex("020000000010")
    ethernet = (client_mac + server_mac if reverse else server_mac + client_mac) + struct.pack("!H", 0x0800)
    return ethernet + ip + tcp + payload


def conversation(request):
    client, server = "198.51.100.20", "192.168.1.10"
    return [
        frame(client, server, 50000, 80, 100, 0, 0x02, ident=1),
        frame(server, client, 80, 50000, 500, 101, 0x12, ident=2, reverse=True),
        frame(client, server, 50000, 80, 101, 501, 0x10, ident=3),
        frame(client, server, 50000, 80, 101, 501, 0x18, request, ident=4),
    ]


def write_pcap(path, packets):
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        stamp = int(time.time())
        for index, packet in enumerate(packets):
            stream.write(struct.pack("<IIII", stamp, index * 1000, len(packet), len(packet)))
            stream.write(packet)


if __name__ == "__main__":
    output = Path(__file__).resolve().parents[1] / "evidence" / "baseline"
    output.mkdir(parents=True, exist_ok=True)
    write_pcap(output / "http-positive.pcap", conversation(
        b"GET /wp-admin/ HTTP/1.1\r\nHost: defender.lab\r\nUser-Agent: sqlmap-lab\r\n\r\n"))
    write_pcap(output / "http-benign.pcap", conversation(
        b"GET /health HTTP/1.1\r\nHost: defender.lab\r\nUser-Agent: curl/8.0\r\n\r\n"))
    write_pcap(output / "http-feedback.pcap", conversation(
        b"GET /lab-repeat HTTP/1.1\r\nHost: defender.lab\r\nUser-Agent: curl/8.0\r\n\r\n"))
