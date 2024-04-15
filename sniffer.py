import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)

def analyze_packet(packet):
    print(packet.summary())

def main():
    interface = "Wi-Fi"
    sniff_packets(interface)

if __name__ == "__main__":
    main()
