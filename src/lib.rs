use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::str::FromStr;






#[pyclass]
struct DataLinkInterface {
    interface_name: String,
}

#[pymethods]
impl DataLinkInterface {
    #[new]
    fn new(interface_name: String) -> Self {
        DataLinkInterface { interface_name }
    }


    #[pyo3(signature = (
        num_packets,
        *,
        protocol = None,
        src_mac = None,
        dst_mac = None,
        src_ip = None,
        dst_ip = None
    ))]
    fn capture_packets(
        &self,
        py: Python,
        num_packets: usize,
        protocol: Option<&str>,
        src_mac: Option<&str>,
        dst_mac: Option<&str>,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
    ) -> PyResult<PyObject> {
        // Find the network interface
        let interface = {
            if cfg!(target_os = "windows") {
                datalink::interfaces()
                    .into_iter()
                    .find(|iface| iface.description == self.interface_name)
            } else {
                datalink::interfaces()
                    .into_iter()
                    .find(|iface| iface.name == self.interface_name)
            }
        }
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "No such network interface: {}",
                self.interface_name
            ))
        })?;

        // Create a channel to receive on
        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(_tx, rx)) => (_tx, rx),
            Ok(_) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "Unhandled channel type",
                ))
            }
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Unable to create channel: {}",
                    e
                )))
            }
        };

        let mut packets = Vec::new();

        while packets.len() < num_packets {
            match rx.next() {
                Ok(packet) => {
                    // Parse the Ethernet packet
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        // Apply MAC address filters
                        if let Some(src_mac_filter) = src_mac {
                            if ethernet.get_source().to_string() != src_mac_filter {
                                continue;
                            }
                        }
                        if let Some(dst_mac_filter) = dst_mac {
                            if ethernet.get_destination().to_string() != dst_mac_filter {
                                continue;
                            }
                        }

                        match ethernet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                // Parse IPv4 packet
                                if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                                    // Apply IP address filters
                                    if let Some(src_ip_filter) = src_ip {
                                        if ipv4_packet.get_source().to_string() != src_ip_filter {
                                            continue;
                                        }
                                    }
                                    if let Some(dst_ip_filter) = dst_ip {
                                        if ipv4_packet.get_destination().to_string()
                                            != dst_ip_filter
                                        {
                                            continue;
                                        }
                                    }

                                    let next_proto = ipv4_packet.get_next_level_protocol();

                                    // Apply protocol filter
                                    if let Some(proto_filter) = protocol {
                                        if proto_filter.eq_ignore_ascii_case("TCP")
                                            && next_proto != IpNextHeaderProtocols::Tcp
                                        {
                                            continue;
                                        } else if proto_filter.eq_ignore_ascii_case("UDP")
                                            && next_proto != IpNextHeaderProtocols::Udp
                                        {
                                            continue;
                                        }
                                    }

                                    // Parse transport layer if needed
                                    let transport_payload = if next_proto == IpNextHeaderProtocols::Tcp {
                                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                            tcp_packet.payload().to_vec()
                                        } else {
                                            continue;
                                        }
                                    } else if next_proto == IpNextHeaderProtocols::Udp {
                                        if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                                            udp_packet.payload().to_vec()
                                        } else {
                                            continue;
                                        }
                                    } else {
                                        ipv4_packet.payload().to_vec()
                                    };

                                    // Prepare packet data
                                    let packet_info = create_packet_info(
                                        py,
                                        &ethernet,
                                        Some(&ipv4_packet),
                                        &transport_payload,
                                    )?;
                                    packets.push(packet_info);
                                }
                            }
                            EtherTypes::Ipv6 => {
                                // Handle IPv6 if needed
                                continue;
                            }
                            _ => {
                                // Other EtherTypes
                                continue;
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "An error occurred while reading: {}",
                        e
                    )));
                }
            }
        }

        let py_packets = PyList::new_bound(py, packets);
        Ok(py_packets.into())
    }

    #[pyo3(signature = (payload, src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port))]
    fn transmit_packet(
        &self,
        payload: &[u8],
        src_mac: &str,
        src_ip: &str,
        src_port: u16,
        dst_mac: &str,
        dst_ip: &str,
        dst_port: u16,
    ) -> PyResult<()> {
        // Parse IP addresses
        let src_ip: Ipv4Addr = src_ip.parse().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid source IP address: {}",
                e
            ))
        })?;
        let dst_ip: Ipv4Addr = dst_ip.parse().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid destination IP address: {}",
                e
            ))
        })?;

        // Parse MAC addresses
        let src_mac = MacAddr::from_str(src_mac).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid source MAC address: {}",
                e
            ))
        })?;
        let dst_mac = MacAddr::from_str(dst_mac).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid destination MAC address: {}",
                e
            ))
        })?;

        // Find the network interface
        let interface = {
            if cfg!(target_os = "windows") {
                datalink::interfaces()
                    .into_iter()
                    .find(|iface| iface.description == self.interface_name)
            } else {
                datalink::interfaces()
                    .into_iter()
                    .find(|iface| iface.name == self.interface_name)
            }
        }
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "No such network interface: {}",
                self.interface_name
            ))
        })?;

        // Create a new UDP packet
        let mut udp_buffer = vec![0u8; MutableUdpPacket::minimum_packet_size() + payload.len()];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Failed to create UDP packet")
        })?;

        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length((MutableUdpPacket::minimum_packet_size() + payload.len()) as u16);
        udp_packet.set_payload(payload);

        // Calculate UDP checksum
        let checksum = pnet::packet::udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            &src_ip,
            &dst_ip,
        );
        udp_packet.set_checksum(checksum);

        // Create a new IPv4 packet
        let mut ip_buffer = vec![
            0u8;
            MutableIpv4Packet::minimum_packet_size() + udp_packet.packet().len()
        ];
        let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Failed to create IPv4 packet")
        })?;

        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(
            (MutableIpv4Packet::minimum_packet_size() + udp_packet.packet().len()) as u16,
        );
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);
        ip_packet.set_payload(udp_packet.packet());

        // Calculate IPv4 checksum
        let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);

        // Create a new Ethernet packet
        let mut ethernet_buffer = vec![
            0u8;
            MutableEthernetPacket::minimum_packet_size() + ip_packet.packet().len()
        ];
        let mut ethernet_packet =
            MutableEthernetPacket::new(&mut ethernet_buffer).ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "Failed to create Ethernet packet",
                )
            })?;

        ethernet_packet.set_destination(dst_mac);
        ethernet_packet.set_source(src_mac);
        ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);
        ethernet_packet.set_payload(ip_packet.packet());

        // Create a channel to send on
        let mut tx = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, _rx)) => tx,
            Ok(_) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "Unhandled channel type",
                ))
            }
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Unable to create channel: {}",
                    e
                )))
            }
        };

        // Send the packet
        tx.send_to(ethernet_packet.packet(), None)
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Failed to send packet")
            })?
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to send packet: {}",
                    e
                ))
            })?;

        Ok(())
    }
}

    

fn create_packet_info(
    py: Python,
    ethernet: &EthernetPacket,
    ipv4: Option<&Ipv4Packet>,
    payload: &[u8],
) -> PyResult<PyObject> {
    let packet_info = PyDict::new_bound(py);
    packet_info.set_item("src_mac", ethernet.get_source().to_string())?;
    packet_info.set_item("dst_mac", ethernet.get_destination().to_string())?;
    packet_info.set_item("ethertype", format!("{:?}", ethernet.get_ethertype()))?;

    if let Some(ipv4_packet) = ipv4 {
        packet_info.set_item("src_ip", ipv4_packet.get_source().to_string())?;
        packet_info.set_item("dst_ip", ipv4_packet.get_destination().to_string())?;
        packet_info.set_item(
            "protocol",
            format!("{:?}", ipv4_packet.get_next_level_protocol()),
        )?;
    }
    packet_info.set_item("payload", PyBytes::new_bound(py, payload))?;

    Ok(packet_info.into())
}

#[pyfunction]
fn list_interfaces() -> PyResult<Vec<String>> {
    let interfaces = datalink::interfaces();
    let interface_names = interfaces
        .into_iter()
        .map(|iface| iface.name)
        .collect::<Vec<String>>();
    Ok(interface_names)
}

#[pymodule]
fn py_pnet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DataLinkInterface>()?;
    m.add_function(wrap_pyfunction!(list_interfaces, m)?)?;
    Ok(())
}