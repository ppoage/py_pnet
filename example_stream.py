"""Example streaming usage for py_pnet."""

import os
import platform
import time
from typing import Any

import py_pnet

INTERFACE_NAME = "en0"
BATCH_SIZE = 1
QUEUE_CAPACITY = 256
RUN_SECONDS = 10


def _configure_windows_dll_path() -> None:
    """Ensure the Windows system DLL path is available for extension loading."""
    if platform.system() != "Windows":
        return

    system_root = os.environ.get("SystemRoot")
    if not system_root:
        return

    system_dir = "System32" if platform.architecture()[0] == "64bit" else "SysWOW64"
    os.add_dll_directory(os.path.join(system_root, system_dir))


def _on_packet(packet: dict[str, Any]) -> None:
    """Handle a single packet callback."""
    payload = packet.get("payload", b"")
    payload_preview = payload[:8] if isinstance(payload, (bytes, bytearray)) else payload
    print(
        "src_mac: {src_mac} | dst_mac: {dst_mac} | src_ip: {src_ip} | dst_ip: {dst_ip} | "
        "payload: {payload}".format(
            src_mac=packet.get("src_mac"),
            dst_mac=packet.get("dst_mac"),
            src_ip=packet.get("src_ip"),
            dst_ip=packet.get("dst_ip"),
            payload=payload_preview,
        )
    )


def _on_batch(packets: list[dict[str, Any]]) -> None:
    """Handle a batch of packets when batch_size > 1."""
    for packet in packets:
        _on_packet(packet)


def main() -> None:
    """Run a short streaming capture and then stop."""
    _configure_windows_dll_path()

    stream = py_pnet.StreamingDataLink(INTERFACE_NAME)
    callback = _on_packet if BATCH_SIZE == 1 else _on_batch

    stream.start(
        callback=callback,
        batch_size=BATCH_SIZE,
        queue_capacity=QUEUE_CAPACITY,
    )

    try:
        time.sleep(RUN_SECONDS)
    except KeyboardInterrupt:
        pass
    finally:
        stream.stop()


if __name__ == "__main__":
    main()
