"""Scapy pcap synthesis.

Crafts a single Ethernet/IP/(TCP|UDP) packet carrying a user payload and writes
it to a pcap, returning the raw bytes. The UI handles the download. This engine
only *crafts and writes* pcap files; it never sends or sniffs live traffic, so
it needs no special privilege.
"""

from __future__ import annotations

import os
import tempfile

from scapy.all import ICMP, IP, TCP, UDP, Ether, wrpcap

# Sane defaults substituted for variables ($...) and "any" so a craftable
# packet always results (matching the draft's choices).
DEFAULT_SRC_IP = "192.168.1.50"
DEFAULT_DST_IP = "10.0.0.99"
DEFAULT_SRC_PORT = 12345
DEFAULT_DST_PORT = 80


def _resolve_ip(value, default: str) -> str:
    s = str(value)
    if "$" in s or s == "any" or s.strip() == "":
        return default
    return s


def _resolve_port(value, default: int) -> int:
    s = str(value)
    if "$" in s or s == "any" or s.strip() == "":
        return default
    # A list or range cannot map to one packet; take the first concrete port.
    first = s.replace(":", ",").split(",")[0].strip()
    try:
        port = int(first)
    except ValueError as exc:
        raise ValueError(f"Could not parse a port from '{value}'.") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"Port {port} is out of range (0-65535).")
    return port


def generate_mock_pcap(
    proto,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    payload,
    is_hex: bool = False,
    icmp_type: int = 8,
    icmp_code: int = 0,
) -> bytes:
    """Build one packet and return it as pcap bytes.

    Args:
        proto: "tcp", "udp" or "icmp" (case-insensitive); anything else -> TCP.
        src_ip, dst_ip: IPs; variables/"any" fall back to sane defaults.
        src_port, dst_port: ports; variables/"any"/lists fall back / first.
        payload: payload string. UTF-8 by default, or hex bytes if is_hex.
        is_hex: when True, parse payload via bytes.fromhex.

    Returns:
        The raw bytes of a single-packet pcap file.

    Raises:
        ValueError: if a hex payload is malformed or a port cannot be parsed.
    """
    s_ip = _resolve_ip(src_ip, DEFAULT_SRC_IP)
    d_ip = _resolve_ip(dst_ip, DEFAULT_DST_IP)
    s_port = _resolve_port(src_port, DEFAULT_SRC_PORT)
    d_port = _resolve_port(dst_port, DEFAULT_DST_PORT)

    pkt = Ether() / IP(src=s_ip, dst=d_ip)
    p = str(proto).lower()
    if p == "icmp":
        # Echo request (type 8, code 0) — the packet every "detect ping" lab
        # rule expects. Ports do not apply to ICMP and are ignored.
        pkt = pkt / ICMP(type=icmp_type, code=icmp_code)
    elif p == "udp":
        pkt = pkt / UDP(sport=s_port, dport=d_port)
    else:
        pkt = pkt / TCP(sport=s_port, dport=d_port, flags="PA")

    if payload:
        if is_hex:
            cleaned = "".join(str(payload).split())
            try:
                raw = bytes.fromhex(cleaned)
            except ValueError as exc:
                raise ValueError(f"Invalid hex payload: {exc}") from exc
        else:
            raw = str(payload).encode("utf-8")
        pkt = pkt / raw

    # Scapy's wrpcap closes the file object it is handed, which makes an
    # in-memory BytesIO unreadable afterwards. Write to a temp file, read the
    # bytes back, then remove it. The result is identical pcap bytes.
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp_path = tmp.name
    tmp.close()
    try:
        wrpcap(tmp_path, [pkt])
        with open(tmp_path, "rb") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
