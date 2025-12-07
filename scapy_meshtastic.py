# You need to import this module into your scapy program in order to register it as a decoder

"""LoRaTap/Meshtastic Moduke
Implements LoRaTap decoding and all the layers down to meshtastic app usage
"""
# scapy.contrib.description: Meshtastic LoRaTap Decoder
# scapy.contrib.status = loads


# decode meshtastic data from LoRaTap packet captures
# L2    LoRaTap
# L3    MeshPacket (if sync_word = 0x2B)
# L4    MeshPayload (if decryptable)
# L5    MeshMessage (if portnum = 1) else
#       MeshApp

import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError
from meshtastic import protobuf as pb
from scapy.config import conf
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    IntField,
    LEIntField,
    NBytesField,
    ShortField,
    StrField,
    XByteField,
    XLEIntField,
)
from scapy.packet import Packet, bind_layers


class LoRaTap(Packet):
    name = "LoRaTap"
    # Decoding the raw LoRa data from packet capture
    # References:
    #   https://github.com/eriknl/LoRaTap/blob/master/loratap.h

    class FreqField(IntField):
        # uint32_t      frequency;
        "LoRa frequency (Hz)"

        def i2repr(self, pkt, x):
            return super().i2repr(pkt, x) + " Hz"

    class PacketRSSIField(ByteField):
        # uint8_t       packet_rssi;
        """
        LoRa packet RSSI, if snr >= 0 then dBm value is -139 + packet_rssi
        otherwise dBm value is -139 + packet_rssi * .25
        """

        def i2repr(self, pkt, x):
            if x == 0xFF:
                return "N/A"
            else:
                if pkt.snr >= 0:
                    rssi = -139 + x
                else:
                    rssi = (-139 + x) / 4
                return str(rssi) + " dBm"

    class MaxRSSIField(ByteField):
        # uint8_t       max_rssi;
        "LoRa receiver max RSSI (dBm value is -139 + rssi)"

        def i2repr(self, pkt, x):
            if x == 0xFF:
                return "N/A"
            else:
                rssi = -139 + x
                return str(rssi) + " dBm"

    class CurrentRSSIField(ByteField):
        # uint8_t       current_rssi;
        "LoRa receiver current RSSI (dBm value is -139 + rssi)"

        def i2repr(self, pkt, x):
            if x == 0xFF:
                return "N/A"
            else:
                rssi = -139 + x
                return str(rssi) + " dBm"

    class SNRField(ByteField):
        # uint8_t       snr;
        "LoRa SNR (dB value is (snr[two's complement])/4)"

        def i2repr(self, pkt, x):
            twos = -(x & 0x80) | (x & 0x7F)  # two's complement
            return str(twos / 4) + " dB"

    fields_desc = [
        # uint8_t       lt_version;     /* LoRatap header version */
        ByteField("lt_version", 0),
        # uint8_t       lt_padding;
        ByteField("lt_padding", 0),
        # uint16_t      lt_length;      /* LoRatap header length */
        ShortField("lt_length", 0),
        FreqField("frequency", None),
        # uint8_t       bandwidth;      /* Channel bandwidth (KHz) in 125 KHz steps */
        ByteEnumField("bandwidth", None, {250: "unknown (250)"}),
        # uint8_t       sf;		        /* LoRa SF (sf_t) [7, 8, 9, 10, 11, 12] */
        # typedef enum  sf  { SF7=7, SF8, SF9, SF10, SF11, SF12 } sf_t;
        ByteEnumField("sf", None, {7: 7, 8: 8, 9: 9, 10: 10, 11: 11}),
        PacketRSSIField("packet_rssi", None),
        MaxRSSIField("max_rssi", None),
        CurrentRSSIField("current_rssi", None),
        SNRField("snr", None),
        # uint8_t       sync_word;      /* LoRa radio sync word [0x34 = LoRaWAN] */
        XByteField("sync_word", None),
    ]


class MeshPacket(Packet):
    name = "MeshPacket"
    # Unencrypted Meshtastic packet header info
    # References:
    #   https://meshtastic.org/docs/overview/mesh-algo/

    class RadioIdField(LEIntField):
        def i2repr(self, pkt, x):
            return "!" + hex(x)[2:]  # !<hex>

    fields_desc = [
        RadioIdField("dst", None),
        RadioIdField("src", None),
        XLEIntField("packet_id", None),
        XByteField("flags", None),
        # reserve 0 bits for these values since they're contained in the flag
        BitField("hop_limit", 0, 0),
        BitField("hop_start", 0, 0),
        BitEnumField("want_ack", 0, 0, {0: False, 1: True}),
        BitEnumField("via_mqtt", 0, 0, {0: False, 1: True}),
        XByteField("channel_hash", None),
        XByteField("next_hop", None),
        XByteField("relay_node", None),
    ]

    def do_dissect(self, s):
        s = super().do_dissect(s)
        # add logic to extract data from flags
        flags = self.flags
        self.hop_limit = (flags & 0x07) >> 0
        self.hop_start = (flags & 0xE0) >> 5
        self.want_ack = (flags & 0x08) >> 3
        self.via_mqtt = (flags & 0x10) >> 4
        return s

    def post_build(self, pkt, pay):
        # and reassemble the flags afterwards
        new_flags = (
            (self._hop_limit << 0)
            | (self._hop_start << 5)
            | (self._want_ack << 3)
            | (self._via_mqtt << 4)
        )
        self.flags = new_flags
        return super().post_build(pkt, pay)


class MQTTPacket(Packet):
    name = "MQTTPacket"
    # the raw data sent as a protobuf via MQTT channels
    # thankfully we can reuse the lower layers once we decode this layer

    class RadioIdField(LEIntField):
        def i2repr(self, pkt, x):
            return "!" + hex(x)[2:]  # !<hex>

    fields_desc = [
        RadioIdField("dst", None),
        RadioIdField("src", None),
        XByteField("packet_id", None),
        # TODO: the rest of these if applicable
    ]  # pyright: ignore # it thinks the typing is a mismatch

    def do_dissect(self, s):
        service_envelope = pb.mqtt_pb2.ServiceEnvelope()
        try:
            mqtt_data = service_envelope.FromString(s)
            self.dst = mqtt_data.packet.to
            self.src = getattr(
                mqtt_data.packet, "from"
            )  # need to do this since from is a reserved word
            self.packet_id = mqtt_data.packet.id
        except DecodeError:
            raise DecodeError(f"Not a service envelope: {s}")
        return mqtt_data.packet.encrypted


class MeshPayload(Packet):
    name = "MeshPayload"
    # Decrypt and decode the meshtastic message protobuf
    # References:
    #   https://meshtastic.org/docs/overview/mesh-algo/
    #   https://meshtastic.org/docs/overview/encryption/
    #   https://buf.build/meshtastic/protobufs

    fields_desc = [
        ByteField("portnum", 0),
        BitField("want_response", None, 1),
        IntField("dst", None),
        IntField("src", None),
        IntField("request_id", None),
        IntField("reply_id", None),
        IntField("emoji", None),
        NBytesField("bitfield", None, 4),  # for extra flags
    ]

    def decrypt(self, payload, mesh_key="AQ=="):
        def crypto_key(key_base64) -> bytearray | None:
            default_psk = bytearray(
                b"\xd4\xf1\xbb\x3a\x20\x29\x07\x59\xf0\xbc\xff\xab\xcf\x4e\x69\x01"
            )
            user_key = bytearray(base64.b64decode(key_base64))
            if len(user_key) == 0:
                # no encryption on the channel
                return None
            elif len(user_key) == 1:
                # key is default key with last byte incremented by the user key
                key = default_psk
                key[-1] = key[-1] + (int(user_key[0]) - 1) % 256
                return key
            elif len(user_key) <= 16:
                # pad out to a 16 byte key
                key = user_key
                key.ljust(16, b"\x00")
                return key
            elif len(user_key) <= 32:
                # pad out to a 32 byte key
                key = user_key
                key.ljust(32, b"\x00")
                return key
            else:
                raise "Error: Channel key is longer than 32 bytes"

        def aes_iv(packet_id, packet_from) -> bytearray:
            # initialization vector for AES crypto
            iv = bytearray(16)  # prefill 16 bytes
            # reversed packet ID
            iv[0:4] = packet_id[::-1]
            # reversed source node
            iv[8:12] = packet_from[::-1]
            return iv

        def decrypt_payload(key, packet_id, src, encrypted_payload) -> bytes:
            # Decrypt the packet using AES
            iv = aes_iv(packet_id.to_bytes(4), src.to_bytes(4))
            mesh_cypher = Cipher(algorithms.AES(key), modes.CTR(iv))
            mesh_decryptor = mesh_cypher.decryptor()
            decrypted = mesh_decryptor.update(encrypted_payload)
            return decrypted

        key = crypto_key(mesh_key)
        meshpkt = self.underlayer
        if key:
            decrypted = decrypt_payload(key, meshpkt.packet_id, meshpkt.src, payload)
            return decrypted
        else:  # not encrypted
            return payload

    # need to decrypt first
    def pre_dissect(self, s):
        return self.decrypt(s)

    def do_dissect(self, s):
        subpacket = pb.mesh_pb2.Data()
        try:
            subpacket = subpacket.FromString(s)
            self.portnum = subpacket.portnum
            self.want_response = subpacket.want_response
            self.dst = subpacket.dest
            self.src = subpacket.source
            self.request_id = subpacket.request_id
            self.reply_id = subpacket.reply_id
            self.emoji = subpacket.emoji
            self.bitfield = subpacket.bitfield
        except DecodeError:
            # assume decryption error/key mismatch
            raise Exception("could not decode with provided key")
        return subpacket.payload


class MeshText(Packet):
    # Plain-text message payloads
    name = "Message"
    fields_desc = [StrField("appname", "TEXT_MESSAGE_APP"), StrField("appdata", "")]

    def do_dissect(self, s):
        self.appdata = s.decode()
        return


class MeshApp(Packet):
    # Non-text message payloads with special behavior per-portnum
    name = "MeshApp"
    fields_desc = [StrField("appname", "text"), StrField("appdata", "")]

    def parse_pb_payload(self, port: int, payload: bytes):
        try:
            if port == pb.portnums_pb2.TEXT_MESSAGE_APP:
                return payload
            elif port == pb.portnums_pb2.NODEINFO_APP:
                nodeinfo = pb.mesh_pb2.User()  # using the User pb per: https://github.com/meshtastic/firmware/issues/912
                return nodeinfo.FromString(payload)
            elif port == pb.portnums_pb2.POSITION_APP:
                position = pb.mesh_pb2.Position()
                return position.FromString(payload)
            elif port == pb.portnums_pb2.TELEMETRY_APP:
                telementry = pb.telemetry_pb2.Telemetry()
                return telementry.FromString(payload)
            elif port == pb.portnums_pb2.STORE_FORWARD_APP:
                store_forward = pb.storeforward_pb2.StoreAndForward()
                return store_forward.ParseFromString(payload)
            elif port == pb.portnums_pb2.TRACEROUTE_APP:
                traceroute = pb.mesh_pb2.RouteDiscovery()
                return traceroute.FromString(payload)
            else:
                NotImplementedError("This app is not yet supported", port, payload)
                return
        except DecodeError:
            raise (f"Could not unpack meshtastic app payload for {port=}")

    def do_dissect(self, s):
        port = self.underlayer.portnum
        self.appname = pb.portnums_pb2.PortNum.Name(port)
        self.appdata = MessageToDict(self.parse_pb_payload(port, s))


# register L2-type/encapsulation 270 as LoRaTap
conf.l2types.register_num2layer(270, LoRaTap)

# require the meshtastic sync_word of 0x2b before decoding as a mesh packet
bind_layers(LoRaTap, MeshPacket, sync_word=0x2B)

# decrypt and extract the payload
bind_layers(MeshPacket, MeshPayload)
bind_layers(MQTTPacket, MeshPayload)

bind_layers(MeshPayload, MeshText, portnum=1)  # special exception for normal text
bind_layers(MeshPayload, MeshApp)  # all other portnums get protobuf decoded
