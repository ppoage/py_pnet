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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;






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
        let interface = find_interface(&self.interface_name)?;

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
                    if let Some(packet_info) = build_packet_info_from_frame(
                        packet,
                        protocol,
                        src_mac,
                        dst_mac,
                        src_ip,
                        dst_ip,
                    ) {
                        let packet_info = packet_info_to_py(py, &packet_info)?;
                        packets.push(packet_info);
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
        let interface = find_interface(&self.interface_name)?;

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

struct PacketInfo {
    src_mac: String,
    dst_mac: String,
    ethertype: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    protocol: Option<String>,
    payload: Vec<u8>,
}

fn build_packet_info_from_frame(
    frame: &[u8],
    protocol: Option<&str>,
    src_mac: Option<&str>,
    dst_mac: Option<&str>,
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
) -> Option<PacketInfo> {
    let ethernet = EthernetPacket::new(frame)?;

    if let Some(src_mac_filter) = src_mac {
        if ethernet.get_source().to_string() != src_mac_filter {
            return None;
        }
    }
    if let Some(dst_mac_filter) = dst_mac {
        if ethernet.get_destination().to_string() != dst_mac_filter {
            return None;
        }
    }

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(ethernet.payload())?;

            if let Some(src_ip_filter) = src_ip {
                if ipv4_packet.get_source().to_string() != src_ip_filter {
                    return None;
                }
            }
            if let Some(dst_ip_filter) = dst_ip {
                if ipv4_packet.get_destination().to_string() != dst_ip_filter {
                    return None;
                }
            }

            let next_proto = ipv4_packet.get_next_level_protocol();

            if let Some(proto_filter) = protocol {
                if proto_filter.eq_ignore_ascii_case("TCP")
                    && next_proto != IpNextHeaderProtocols::Tcp
                {
                    return None;
                } else if proto_filter.eq_ignore_ascii_case("UDP")
                    && next_proto != IpNextHeaderProtocols::Udp
                {
                    return None;
                }
            }

            let transport_payload = if next_proto == IpNextHeaderProtocols::Tcp {
                TcpPacket::new(ipv4_packet.payload())
                    .map(|tcp_packet| tcp_packet.payload().to_vec())?
            } else if next_proto == IpNextHeaderProtocols::Udp {
                UdpPacket::new(ipv4_packet.payload())
                    .map(|udp_packet| udp_packet.payload().to_vec())?
            } else {
                ipv4_packet.payload().to_vec()
            };

            Some(PacketInfo {
                src_mac: ethernet.get_source().to_string(),
                dst_mac: ethernet.get_destination().to_string(),
                ethertype: format!("{:?}", ethernet.get_ethertype()),
                src_ip: Some(ipv4_packet.get_source().to_string()),
                dst_ip: Some(ipv4_packet.get_destination().to_string()),
                protocol: Some(format!("{:?}", next_proto)),
                payload: transport_payload,
            })
        }
        EtherTypes::Ipv6 => None,
        _ => None,
    }
}

fn packet_info_to_py(py: Python, info: &PacketInfo) -> PyResult<PyObject> {
    let packet_info = PyDict::new_bound(py);
    packet_info.set_item("src_mac", &info.src_mac)?;
    packet_info.set_item("dst_mac", &info.dst_mac)?;
    packet_info.set_item("ethertype", &info.ethertype)?;
    if let Some(ref src_ip) = info.src_ip {
        packet_info.set_item("src_ip", src_ip)?;
    }
    if let Some(ref dst_ip) = info.dst_ip {
        packet_info.set_item("dst_ip", dst_ip)?;
    }
    if let Some(ref protocol) = info.protocol {
        packet_info.set_item("protocol", protocol)?;
    }
    packet_info.set_item("payload", PyBytes::new_bound(py, &info.payload))?;
    Ok(packet_info.into())
}

fn find_interface(interface_name: &str) -> PyResult<datalink::NetworkInterface> {
    let interface = if cfg!(target_os = "windows") {
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.description == interface_name)
    } else {
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
    };

    interface.ok_or_else(|| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "No such network interface: {}",
            interface_name
        ))
    })
}

#[pyclass]
struct StreamingDataLink {
    interface_name: String,
    stop_flag: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    capture_thread: Option<thread::JoinHandle<()>>,
    callback_thread: Option<thread::JoinHandle<()>>,
}

#[pymethods]
impl StreamingDataLink {
    #[new]
    fn new(interface_name: String) -> Self {
        StreamingDataLink {
            interface_name,
            stop_flag: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
            capture_thread: None,
            callback_thread: None,
        }
    }

    #[pyo3(signature = (
        callback,
        *,
        batch_size = 1,
        queue_capacity = 1024,
        protocol = None,
        src_mac = None,
        dst_mac = None,
        src_ip = None,
        dst_ip = None
    ))]
    fn start(
        &mut self,
        py: Python,
        callback: PyObject,
        batch_size: usize,
        queue_capacity: usize,
        protocol: Option<&str>,
        src_mac: Option<&str>,
        dst_mac: Option<&str>,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
    ) -> PyResult<()> {
        if batch_size == 0 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "batch_size must be >= 1",
            ));
        }
        if queue_capacity == 0 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "queue_capacity must be >= 1",
            ));
        }
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "StreamingDataLink is already running",
            ));
        }
        if !callback.bind(py).is_callable() {
            self.running.store(false, Ordering::SeqCst);
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "callback must be callable",
            ));
        }

        let interface = find_interface(&self.interface_name)?;
        let config = datalink::Config {
            read_timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        match datalink::channel(&interface, config) {
            Ok(Ethernet(_tx, _rx)) => {}
            Ok(_) => {
                self.running.store(false, Ordering::SeqCst);
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "Unhandled channel type",
                ));
            }
            Err(e) => {
                self.running.store(false, Ordering::SeqCst);
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Unable to create channel: {}",
                    e
                )));
            }
        }

        self.stop_flag.store(false, Ordering::SeqCst);

        let (sender, receiver) = mpsc::sync_channel::<Vec<PacketInfo>>(queue_capacity);
        let stop_flag_capture = Arc::clone(&self.stop_flag);
        let running_capture = Arc::clone(&self.running);
        let interface_name = self.interface_name.clone();
        let protocol = protocol.map(|value| value.to_string());
        let src_mac = src_mac.map(|value| value.to_string());
        let dst_mac = dst_mac.map(|value| value.to_string());
        let src_ip = src_ip.map(|value| value.to_string());
        let dst_ip = dst_ip.map(|value| value.to_string());

        let capture_thread = thread::spawn(move || {
            let interface = match find_interface(&interface_name) {
                Ok(interface) => interface,
                Err(_) => {
                    running_capture.store(false, Ordering::SeqCst);
                    return;
                }
            };

            let config = datalink::Config {
                read_timeout: Some(Duration::from_millis(100)),
                ..Default::default()
            };
            let mut rx = match datalink::channel(&interface, config) {
                Ok(Ethernet(_tx, rx)) => rx,
                _ => {
                    running_capture.store(false, Ordering::SeqCst);
                    return;
                }
            };

            let mut batch = Vec::with_capacity(batch_size);

            while !stop_flag_capture.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(packet_info) = build_packet_info_from_frame(
                            packet,
                            protocol.as_deref(),
                            src_mac.as_deref(),
                            dst_mac.as_deref(),
                            src_ip.as_deref(),
                            dst_ip.as_deref(),
                        ) {
                            batch.push(packet_info);
                        } else {
                            continue;
                        }

                        if batch.len() >= batch_size {
                            let to_send = std::mem::take(&mut batch);
                            match sender.try_send(to_send) {
                                Ok(()) => {
                                    batch = Vec::with_capacity(batch_size);
                                }
                                Err(mpsc::TrySendError::Full(_dropped)) => {
                                    batch = Vec::with_capacity(batch_size);
                                }
                                Err(mpsc::TrySendError::Disconnected(_batch)) => {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::TimedOut {
                            continue;
                        }
                        break;
                    }
                }
            }

            if !batch.is_empty() {
                let _ = sender.try_send(batch);
            }

            running_capture.store(false, Ordering::SeqCst);
        });

        let stop_flag_callback = Arc::clone(&self.stop_flag);
        let running_callback = Arc::clone(&self.running);
        let callback_thread = thread::spawn(move || {
            let callback = callback;

            while let Ok(batch) = receiver.recv() {
                if batch.is_empty() {
                    continue;
                }
                let call_result = Python::with_gil(|py| -> PyResult<()> {
                    if batch_size == 1 {
                        let packet_info = packet_info_to_py(py, &batch[0])?;
                        callback.call1(py, (packet_info,))?;
                    } else {
                        let mut packets = Vec::with_capacity(batch.len());
                        for info in &batch {
                            packets.push(packet_info_to_py(py, info)?);
                        }
                        let py_packets = PyList::new_bound(py, packets);
                        callback.call1(py, (py_packets,))?;
                    }
                    Ok(())
                });

                if let Err(err) = call_result {
                    Python::with_gil(|py| {
                        err.print(py);
                    });
                    stop_flag_callback.store(true, Ordering::SeqCst);
                    break;
                }
            }

            running_callback.store(false, Ordering::SeqCst);
        });

        self.capture_thread = Some(capture_thread);
        self.callback_thread = Some(callback_thread);

        Ok(())
    }

    fn stop(&mut self) -> PyResult<()> {
        self.stop_internal();
        Ok(())
    }
}

impl StreamingDataLink {
    fn stop_internal(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.capture_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.callback_thread.take() {
            let _ = handle.join();
        }
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Drop for StreamingDataLink {
    fn drop(&mut self) {
        self.stop_internal();
    }
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
    m.add_class::<StreamingDataLink>()?;
    m.add_function(wrap_pyfunction!(list_interfaces, m)?)?;
    Ok(())
}
