use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::sync::{Arc, Mutex};
use std::thread;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

#[pyclass]
struct PacketSniffer {
    interface_name: String,
    stop_flag: Arc<Mutex<bool>>,
}

#[pymethods]
impl PacketSniffer {
    #[new]
    fn new(interface_name: String) -> Self {
        PacketSniffer {
            interface_name,
            stop_flag: Arc::new(Mutex::new(false)),
        }
    }

    fn sniff(&self, py: Python, callback: PyObject) -> PyResult<()> {
        let stop_flag = self.stop_flag.clone();
        let interface_name = self.interface_name.clone();
        let callback = callback.clone_ref(py);

        // Start sniffing in a new thread
        thread::spawn(move || {
            if let Err(e) = capture_packets(&interface_name, stop_flag, callback) {
                eprintln!("Error capturing packets: {}", e);
            }
        });

        Ok(())
    }

    fn stop(&self) {
        let mut stop = self.stop_flag.lock().unwrap();
        *stop = true;
    }
}

fn capture_packets(
    interface_name: &str,
    stop_flag: Arc<Mutex<bool>>,
    callback: PyObject,
) -> Result<(), String> {
    // Find the network interface
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| format!("No such network interface: {}", interface_name))?;

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, rx)) => (_tx, rx),
        Ok(_) => return Err("Unhandled channel type".to_string()),
        Err(e) => return Err(format!("Unable to create channel: {}", e)),
    };

    // Packet capturing loop
    loop {
        {
            let stop = stop_flag.lock().unwrap();
            if *stop {
                break;
            }
        }

        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    // Prepare packet data
                    let src_mac = ethernet.get_source().to_string();
                    let dst_mac = ethernet.get_destination().to_string();
                    let ethertype = format!("{:?}", ethernet.get_ethertype());
                    let payload = ethernet.payload().to_vec();

                    // Call the Python callback with packet info
                    Python::with_gil(|py| {
                        let packet_info = PyDict::new_bound(py);
                        packet_info.set_item("src_mac", src_mac).unwrap();
                        packet_info.set_item("dst_mac", dst_mac).unwrap();
                        packet_info.set_item("ethertype", ethertype).unwrap();
                        packet_info
                            .set_item("payload", PyBytes::new_bound(py, &payload))
                            .unwrap();

                        if let Err(e) = callback.call1(py, (packet_info,)) {
                            eprintln!("Callback error: {:?}", e);
                        }
                    });
                } else {
                    eprintln!("Invalid Ethernet packet");
                }
            }
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
            }
        }
    }

    Ok(())
}

#[pymodule]
fn py_pnet( m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PacketSniffer>()?;
    Ok(())
}


// #[pymodule]
// fn pnet_sniffer(py: Python, m: &PyModule) -> PyResult<()> {
//     m.add_class::<PacketSniffer>()?;
//     Ok(())
// }