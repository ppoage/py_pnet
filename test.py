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


def main():
    # List available interfaces
    interfaces = list_interfaces()
    print("Available interfaces:")
    for iface in interfaces:
        #print("test")
        print(f"- {iface}")

    # Replace with your interface name
    interface_name = "en0"  # Update this to match your interface

    sniffer = DataLinkInterface(interface_name)

    # Capture 5 packets without any filters
    print("\nCapturing 100 packets without filters:")
    packets = sniffer.capture_packets(100)
    for pkt in packets:
        print(pkt['payload'])

    #To Transmit:
    #sniffer.transmit_packet(packet_data, num_packets=5)

if __name__ == "__main__":
    main()