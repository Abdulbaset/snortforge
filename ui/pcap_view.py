"""Phase 3 UI: Scapy pcap synthesis tab."""

from __future__ import annotations

import streamlit as st

from engine.pcap_engine import generate_mock_pcap


def render_pcap() -> None:
    st.subheader("PCAP Synthesis")
    st.caption(
        "Crafts a single packet and writes a .pcap. Open it in Wireshark to "
        "confirm the crafted packet and payload bytes. No live traffic is sent."
    )

    c1, c2 = st.columns(2)
    with c1:
        proto = st.selectbox("Protocol", ["tcp", "udp"], index=0)
        src_ip = st.text_input("Source IP", value="192.168.1.50")
        src_port = st.text_input("Source port", value="12345")
    with c2:
        st.write("")
        st.write("")
        dst_ip = st.text_input("Destination IP", value="10.0.0.99")
        dst_port = st.text_input("Destination port", value="80")

    is_hex = st.toggle("Payload is hex", value=False)
    payload = st.text_area(
        "Payload",
        value="GET /admin HTTP/1.1\r\nHost: target\r\n\r\n" if not is_hex else "41424344",
        height=120,
    )

    if st.button("Generate .pcap"):
        try:
            data = generate_mock_pcap(
                proto, src_ip, dst_ip, src_port, dst_port, payload, is_hex=is_hex
            )
        except ValueError as exc:
            st.error(str(exc))
            return
        st.success(f"Crafted 1 packet ({len(data)} bytes).")
        st.download_button(
            "⬇ Download .pcap",
            data=data,
            file_name="snortforge_capture.pcap",
            mime="application/vnd.tcpdump.pcap",
        )
