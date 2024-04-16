import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)

def analyze_packet(packet):
    print(packet.summary())

def main():
    interface = "Wi-Fi" #instead of Wi-Fi write your network interface here, You can check it by using "ipconfig" command on windows command line, and "ifconfig" command on linux terminal.
    sniff_packets(interface)

if __name__ == "__main__":
    main()
