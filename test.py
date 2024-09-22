import os
import platform
import sys
import time

#Add System32 to the DLL search path on Windows
if platform.system() == 'Windows':
    if platform.architecture()[0] == '64bit':
        system_dir = os.path.join(os.environ['SystemRoot'], 'System32')
    else:
        system_dir = os.path.join(os.environ['SystemRoot'], 'SysWOW64')
    os.add_dll_directory(system_dir)

from py_pnet import DataLinkInterface, list_interfaces

def return_valid_interfaces():
    # List available interfaces
    interfaces = list_interfaces()
    print("Available interfaces:")
    for iface in interfaces:
        #print("test")
        print(f"- {iface}")

def udp_transmit():

    interface_name = "en0"  # Update this to match your interface
    interface = DataLinkInterface(interface_name)

    payload = b'Hello, World?'

    # Specify source and destination MAC addresses
    src_mac = '00:11:22:33:44:55'
    dst_mac = '66:77:88:99:AA:BB'

    # Specify source and destination IPs and ports
    src_ip = '192.168.1.2'
    src_port = 12345
    dst_ip = '192.168.1.3'
    dst_port = 54321

    # Transmit the packet
    interface.transmit_packet(
        payload,
        src_mac,
        src_ip,
        src_port,
        dst_mac,
        dst_ip,
        dst_port
    )

def udp_receive():
        # Replace with your interface name
    interface_name = "en0"  # Update this to match your interface

    sniffer = DataLinkInterface(interface_name)

    # Capture 100 packets without any filters
    print("\nCapturing 100 packets without filters:")
    packets = sniffer.capture_packets(100)
    for pkt in packets: #Only prints first 8 bytes of payload
        print(f"src_mac: {pkt['src_mac']} | dst_mac {pkt['dst_mac']} | ethertype {pkt['ethertype']} | src_ip {pkt['src_ip']} | dst_ip {pkt['dst_ip']} | payload {pkt['payload'][0:8]}")

def main():

    #To List Network Interfaces:
    #return_valid_interfaces()

    #To Receive:
    udp_receive()   

    #To Transmit:
    #udp_transmit()

if __name__ == "__main__":
    main()