import os
import platform
import pnet_sniffer

# Add System32 to the DLL search path on Windows
if platform.system() == 'Windows':
    if platform.architecture()[0] == '64bit':
        system_dir = os.path.join(os.environ['SystemRoot'], 'System32')
    else:
        system_dir = os.path.join(os.environ['SystemRoot'], 'SysWOW64')
    os.add_dll_directory(system_dir)

def main():
    # List available interfaces
    interfaces = pnet_sniffer.list_interfaces()
    print("Available interfaces:")
    for iface in interfaces:
        print(f"- {iface}")

    # Replace with your interface name
    interface_name = "Ethernet"  # Update this to match your interface

    sniffer = pnet_sniffer.PacketSniffer(interface_name)

    # Capture 5 packets without any filters
    print("\nCapturing 5 packets without filters:")
    packets = sniffer.capture_packets(5)
    for pkt in packets:
        print(pkt)

if __name__ == "__main__":
    main()