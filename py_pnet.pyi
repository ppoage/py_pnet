"""Type stubs for py_pnet."""

from typing import Any, Callable, TypeAlias

Packet: TypeAlias = dict[str, Any]
PacketBatch: TypeAlias = list[Packet]
PacketCallback: TypeAlias = Callable[[Packet | PacketBatch], Any]


class DataLinkInterface:
    """Capture and transmit packets on a data link interface."""

    def __init__(self, interface_name: str) -> None: ...

    def capture_packets(
        self,
        num_packets: int,
        *,
        protocol: str | None = ...,
        src_mac: str | None = ...,
        dst_mac: str | None = ...,
        src_ip: str | None = ...,
        dst_ip: str | None = ...,
    ) -> list[Packet]: ...

    def transmit_packet(
        self,
        payload: bytes,
        src_mac: str,
        src_ip: str,
        src_port: int,
        dst_mac: str,
        dst_ip: str,
        dst_port: int,
    ) -> None: ...


class StreamingDataLink:
    """Stream packets and invoke a Python callback."""

    def __init__(self, interface_name: str) -> None: ...

    def start(
        self,
        callback: PacketCallback,
        *,
        batch_size: int = ...,
        queue_capacity: int = ...,
        protocol: str | None = ...,
        src_mac: str | None = ...,
        dst_mac: str | None = ...,
        src_ip: str | None = ...,
        dst_ip: str | None = ...,
    ) -> None: ...

    def stop(self) -> None: ...


def list_interfaces() -> list[str]: ...
