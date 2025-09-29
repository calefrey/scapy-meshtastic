import argparse
import json
import sys

from scapy.all import sniff

from db_tools import Databse
from scapy_meshtastic import LoRaTap, MeshApp, MeshPacket, MeshPayload, MeshText, pb

parser = argparse.ArgumentParser(
    description="Processes pcap files and saves them to a databse"
)

parser.add_argument("filename")

args = parser.parse_args()


def process_packet(pkt):
    # LoRaTap -> MeshPacket -> MeshPayload -> MeshApp OR MeshText
    assert pkt.haslayer(LoRaTap)  # It better!

    packet_data = {}
    packet_data["_timestamp"] = str(pkt.time)  # use the packet's capture time

    if pkt.haslayer(MeshPacket):  # src, dst, packet id, etc
        packet_data.update(
            {
                "src": "!" + hex(pkt.src)[2:],
                "dst": "!" + hex(pkt.dst)[2:],
                "packet_id": hex(pkt.packet_id),
            }
        )
        # include all the MeshPacket layer data for e.g. hop counts
        packet_data["packet"] = json.dumps(pkt[MeshPacket].fields)

    if pkt.haslayer(MeshPayload):  # portnum, want_response, request/reply ids
        packet_data["payload"] = json.dumps(pkt[MeshPayload].fields)

    if pkt.haslayer(MeshApp):  # app data including node update logic
        packet_data["appname"] = pkt.appname.decode()
        packet_data["appdata"] = json.dumps(pkt.appdata)

        # update the node table
        if pkt.portnum == pb.portnums_pb2.NODEINFO_APP:
            nodeinfo = pkt.appdata
            nodeinfo.update({"_id": "!" + hex(pkt.src)[2:]})
            nodeinfo["last_updated"] = str(pkt.time)
            db.insert("nodes", nodeinfo, on_confict="REPLACE")

    elif pkt.haslayer(MeshText):  # plain old text message
        packet_data["appname"] = pkt.appname.decode()
        packet_data["appdata"] = json.dumps(pkt[MeshText].appdata.decode())

    db.insert("data", packet_data, on_confict="IGNORE")


db = Databse("database.db")


if __name__ == "__main__":
    if args.filename == "-":
        print("Processing from stdin")
        try:
            sniff(offline=sys.stdin.buffer, prn=process_packet)
        except KeyboardInterrupt:
            print("Exiting")
        finally:
            db.close()

    elif args.filename:
        sniff(offline=args.filename, prn=process_packet)
