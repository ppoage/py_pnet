import ctypes
import os
import platform
import sys
import time

if platform.system() == 'Windows':
    if platform.architecture()[0] == '64bit':
        system_dir = os.path.join(os.environ['SystemRoot'], 'System32')
    else:
        system_dir = os.path.join(os.environ['SystemRoot'], 'SysWOW64')

    # Load the DLLs
    ctypes.windll.LoadLibrary(os.path.join(system_dir, 'Packet.dll'))
    ctypes.windll.LoadLibrary(os.path.join(system_dir, 'wpcap.dll'))


print(sys.version)
sys.path.insert(0, "/Applications/Code/Code/py_pnet")
#import py_pnet
import py_pnet.py_pnet

print(py_pnet.py_pnet)

def packet_callback(packet_info):
    src_mac = packet_info['src_mac']
    dst_mac = packet_info['dst_mac']
    ethertype = packet_info['ethertype']
    payload = packet_info['payload']  # This is bytes

    #print("Packet Received")
    #print(f"Time: Packet: {src_mac} -> {dst_mac}, Type: {ethertype}, Payload Length: {len(payload)}")
    print(f"Time: {time.perf_counter()} Packet:  -> {dst_mac}, Type: {ethertype}, Payload Length: {len(payload)}, Data: {payload[:8]}")

# Initialize the sniffer
sniffer = py_pnet.py_pnet.PacketSniffer("en0")  # Replace "eth0" with your interface

# Start sniffing
sniffer.sniff(packet_callback)

# Let it run for 10 seconds
time.sleep(10)

# Stop sniffing
sniffer.stop()

#py_pnet.py_pnet