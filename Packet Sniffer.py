from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):

    if packet.haslayer(IP):
  
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"\n[+] Packet Captured:")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        
  
        if proto == 6 and packet.haslayer(TCP):  
            print(f"Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif proto == 17 and packet.haslayer(UDP):  
            print(f"Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        
        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load}")


sniff(prn=packet_callback, filter="ip", count=10)
