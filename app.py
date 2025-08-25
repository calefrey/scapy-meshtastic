from scapy.all import sniff
from scapy_meshtastic import MeshText, MeshApp


def print_packet(pkt):
    def i2repr(x):
        return "!" + hex(x)[2:]

    print(f"{i2repr(pkt.src)} -> {i2repr(pkt.dst)}")
    if pkt.haslayer(MeshText) or pkt.haslayer(MeshApp):
        # add logic here for e.g. building a database
        print(pkt.portnum, pkt.appname.decode())
        print(pkt.appdata)
    else:
        print("Could not decode")


sniff(offline="capture.pcap", prn=print_packet)
