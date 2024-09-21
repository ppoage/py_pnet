use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;

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

    #[pyo3(signature = (packet, num_packets=None))]
    fn transmit_packet(
        &self,
        packet: &[u8],
        num_packets: Option<usize>,
    ) -> PyResult<()> {
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

        // Create a channel to send on
        let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, _rx)) => (tx, _rx),
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

        let packet_bytes = packet;

        let packet_size = packet_bytes.len();

        let num_packets = num_packets.unwrap_or(1);
        let num_packets = if num_packets < 1 { 1 } else { num_packets };

        for _ in 0..num_packets {
            let send_result = tx.build_and_send(1, packet_size, &mut |new_packet: &mut [u8]| {
                new_packet.copy_from_slice(packet_bytes);
            });
        
            match send_result {
                Some(Ok(())) => {
                    // Packet sent successfully
                }
                Some(Err(e)) => {
                    return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "Failed to send packet: {}",
                        e
                    )));
                }
                None => {
                    return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        "DataLinkSender has been closed",
                    ));
                }
            }
        }

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