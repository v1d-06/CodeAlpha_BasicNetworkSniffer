from scapy.all import sniff,Ether,IP,TCP,UDP,ICMP,Raw,ARP
def packet_CallBack(packet):
    print("="*80)
    if Ether in packet:
        eth=packet[Ether]
        print(f"Ethernet frame: {eth.src}->{eth.dst} type :{hex(eth.type)}")
    
    if IP in packet:
        ip_layer=packet[IP]
        print(f"IP packet: {ip_layer.src}->{ip_layer.dst} protocol: {ip_layer.proto}") 
        if TCP in packet:
            tcp_layer=packet[TCP]
            print(f"TCP segment:{tcp_layer.sport}->{tcp_layer.dport},flags:{tcp_layer.flags}")
        elif UDP in packet:
            udp_layer=packet[UDP]
            print(f"UDP datagram:{udp_layer.sport}->{udp_layer.dport},length:{udp_layer.len}")
        elif ICMP in packet:
            icmp_layer=packet[ICMP]
            print(f"ICMP packet:type:{icmp_layer.type},code:{icmp_layer.code}")
    elif ARP in packet:
        arp=packet[ARP]
        print(f"ARP packet:{arp.psrc}->{arp.pdst},Op:{arp.op}")
    else:
        print("non IP packet")
    if Raw in packet:
        raw_data=packet[Raw].load
        try:
            decode_data=raw_data.decode(error='replace')
            print(f"payload:\n{decode_data}")
        except Exception:
            print(f"Raw payloads(bytes):{raw_data}")

def main():
    print("starting basic network sniffer...Press ctrl+C to stop")
    sniff(prn=packet_CallBack,store=0)
if __name__=="__main__":
    main()
