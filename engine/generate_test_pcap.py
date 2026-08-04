#!/usr/bin/env python3
"""
Builds a small sample .pcap containing TLS ClientHello packets (with SNI),
a plain HTTP request, and a UDP packet, so the DPI engine has real traffic
to parse and classify without needing a live network capture.
"""
import struct
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


def build_tls_client_hello(sni: str) -> bytes:
    """Hand-builds a minimal TLS 1.2 ClientHello record containing an SNI extension."""
    server_name = sni.encode()
    server_name_entry = b"\x00" + struct.pack(">H", len(server_name)) + server_name
    server_name_list = struct.pack(">H", len(server_name_entry)) + server_name_entry
    ext_sni = struct.pack(">H", 0x0000) + struct.pack(">H", len(server_name_list)) + server_name_list

    extensions_block = struct.pack(">H", len(ext_sni)) + ext_sni

    session_id = b""
    cipher_suites = b"\x00\x2f\x00\x35"
    compression_methods = b"\x00"

    client_hello_body = (
        b"\x03\x03"                                            # client_version (TLS 1.2)
        + (b"\x00" * 32)                                        # random
        + struct.pack("B", len(session_id)) + session_id
        + struct.pack(">H", len(cipher_suites)) + cipher_suites
        + struct.pack("B", len(compression_methods)) + compression_methods
        + extensions_block
    )

    handshake = b"\x01" + struct.pack(">I", len(client_hello_body))[1:] + client_hello_body
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def main():
    packets = []
    domains = ["www.youtube.com", "www.facebook.com", "www.google.com", "github.com", "www.netflix.com"]
    src_ip = "192.168.1.100"
    base_port = 50000

    for i, domain in enumerate(domains):
        dst_ip = f"172.217.{i}.10"
        sport = base_port + i

        # Simplified 3-way handshake so the engine sees a realistic flow.
        syn    = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="S", seq=0)
        synack = Ether() / IP(src=dst_ip, dst=src_ip) / TCP(sport=443, dport=sport, flags="SA", seq=0, ack=1)
        ack    = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="A", seq=1, ack=1)

        client_hello = build_tls_client_hello(domain)
        hello_pkt = (
            Ether() / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=443, flags="PA", seq=1, ack=1)
            / Raw(load=client_hello)
        )

        packets.extend([syn, synack, ack, hello_pkt])

    # One plain-HTTP request, to exercise the Host: header path too.
    http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
    http_pkt = (
        Ether() / IP(src=src_ip, dst="93.184.216.34")
        / TCP(sport=base_port + 100, dport=80, flags="PA")
        / Raw(load=http_req)
    )
    packets.append(http_pkt)

    # One UDP packet, so the engine has non-TCP traffic to count too.
    dns_pkt = Ether() / IP(src=src_ip, dst="8.8.8.8") / UDP(sport=base_port + 200, dport=53) / Raw(load=b"\x00" * 20)
    packets.append(dns_pkt)

    wrpcap("test_traffic.pcap", packets)
    print(f"Generated test_traffic.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
