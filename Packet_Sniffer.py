import scapy.all as scapy
from scapy_http import http
import optparse

def user_inputs():
    parse_object=optparse.OptionParser()
    parse_object.add_option("-i","--interface",dest="interface",help="name of interface")

    return parse_object.parse_args()

def packet_sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packet)

def analyze_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

(user_input,arguments)=user_inputs()
packet_sniffer(user_input.interface)