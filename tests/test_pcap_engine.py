"""Tests for engine/pcap_engine.py (Phase 3 pcap acceptance criteria)."""

import io

import pytest
from scapy.all import TCP, UDP, rdpcap

from engine.pcap_engine import (
    DEFAULT_DST_IP,
    DEFAULT_SRC_IP,
    generate_mock_pcap,
)


def _read(pcap_bytes):
    return rdpcap(io.BytesIO(pcap_bytes))


def test_returns_bytes_and_parses():
    data = generate_mock_pcap("tcp", "1.1.1.1", "2.2.2.2", 1234, 80, "hello")
    assert isinstance(data, bytes)
    pkts = _read(data)
    assert len(pkts) == 1


def test_payload_bytes_present_utf8():
    data = generate_mock_pcap("tcp", "1.1.1.1", "2.2.2.2", 1234, 80, "MALWARE")
    pkts = _read(data)
    raw = bytes(pkts[0].payload.payload.payload)  # IP/TCP/Raw
    assert b"MALWARE" in bytes(pkts[0])
    assert b"MALWARE" in raw


def test_hex_payload_mode():
    # "4142" -> b"AB"
    data = generate_mock_pcap(
        "tcp", "1.1.1.1", "2.2.2.2", 1234, 80, "4142", is_hex=True
    )
    pkts = _read(data)
    assert b"AB" in bytes(pkts[0])


def test_invalid_hex_raises():
    with pytest.raises(ValueError):
        generate_mock_pcap("tcp", "1.1.1.1", "2.2.2.2", 1234, 80, "zzzz", is_hex=True)


def test_udp_protocol():
    data = generate_mock_pcap("udp", "1.1.1.1", "2.2.2.2", 1234, 53, "q")
    pkts = _read(data)
    assert pkts[0].haslayer(UDP)


def test_tcp_default_for_non_udp():
    data = generate_mock_pcap("tcp", "1.1.1.1", "2.2.2.2", 1234, 80, "q")
    pkts = _read(data)
    assert pkts[0].haslayer(TCP)


def test_variable_and_any_defaults_substituted():
    data = generate_mock_pcap("tcp", "$HOME_NET", "any", "$HTTP_PORTS", "any", "x")
    pkts = _read(data)
    ip = pkts[0].payload  # IP layer
    assert ip.src == DEFAULT_SRC_IP
    assert ip.dst == DEFAULT_DST_IP


def test_port_list_takes_first():
    data = generate_mock_pcap("tcp", "1.1.1.1", "2.2.2.2", "1234,5678", "80,443", "x")
    pkts = _read(data)
    tcp = pkts[0].getlayer(TCP)
    assert tcp.sport == 1234
    assert tcp.dport == 80


def test_empty_payload_ok():
    data = generate_mock_pcap("tcp", "1.1.1.1", "2.2.2.2", 1234, 80, "")
    assert len(_read(data)) == 1
