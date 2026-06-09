"""Phase 3 UI: Scapy pcap synthesis tab."""

from __future__ import annotations

import streamlit as st

from engine.pcap_engine import generate_mock_pcap

_FILENAME = "snortforge_capture.pcap"


def _payload_byte_count(payload: str, is_hex: bool) -> int:
    if not payload:
        return 0
    if is_hex:
        try:
            return len(bytes.fromhex("".join(payload.split())))
        except ValueError:
            return 0
    return len(payload.encode("utf-8"))


def render_pcap() -> None:
    st.subheader("PCAP Synthesis")
    st.caption(
        "Crafts a single packet and writes a .pcap. Open it in Wireshark to "
        "confirm the crafted packet and payload bytes. No live traffic is sent."
    )

    proto = st.selectbox("Protocol", ["tcp", "udp"], index=0)

    r1c1, r1c2 = st.columns(2)
    with r1c1:
        src_ip = st.text_input("Source IP", value="192.168.1.50")
    with r1c2:
        src_port = st.text_input("Source port", value="12345")

    r2c1, r2c2 = st.columns(2)
    with r2c1:
        dst_ip = st.text_input("Destination IP", value="10.0.0.99")
    with r2c2:
        dst_port = st.text_input("Destination port", value="80")

    is_hex = st.toggle("Payload is hex", value=False)
    payload = st.text_area(
        "Payload",
        value="GET /admin HTTP/1.1\r\nHost: target\r\n\r\n" if not is_hex else "41424344",
        height=120,
    )

    if st.button("Generate .pcap", type="primary"):
        try:
            data = generate_mock_pcap(
                proto, src_ip, dst_ip, src_port, dst_port, payload, is_hex=is_hex
            )
        except ValueError as exc:
            st.session_state.pop("pcap_data", None)
            st.error(str(exc))
            return
        st.session_state["pcap_data"] = data
        st.session_state["pcap_meta"] = {
            "proto": proto.upper(),
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "payload_bytes": _payload_byte_count(payload, is_hex),
            "packet_bytes": len(data),
            "filename": _FILENAME,
        }

    data = st.session_state.get("pcap_data")
    meta = st.session_state.get("pcap_meta")
    if data and meta:
        st.success("Crafted 1 packet.")
        st.markdown(
            f"- **Protocol:** {meta['proto']}\n"
            f"- **Flow:** {meta['src']} → {meta['dst']}\n"
            f"- **Payload:** {meta['payload_bytes']} bytes "
            f"(packet {meta['packet_bytes']} bytes)\n"
            f"- **File:** `{meta['filename']}`"
        )
        st.download_button(
            "⬇ Download .pcap",
            data=data,
            file_name=meta["filename"],
            mime="application/vnd.tcpdump.pcap",
            type="primary",
        )
