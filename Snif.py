from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"IP Packet: {src_ip} -> {dst_ip}")

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP Port: {src_port} -> {dst_port}")

    if UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"UDP Port: {src_port} -> {dst_port}")

# Capturer et afficher les paquets en temps réel
sniff(prn=packet_callback, count=10)

