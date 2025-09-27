import time
import struct


def make_header(l2type: int = 270):
    """Write PCAP header bytes including magic packet.

    l2type is PCAP link-layer type, per https://www.ietf.org/archive/id/draft-ietf-opsawg-pcaplinktype-11.html
    """
    #                       PCAP Header format
    #      0-------------- 1---------------2---------------3--------------
    #      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  0 |                   Magic Number (uint32) = 0xA1B2C3D4            |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  4 |   Major Version (uint16) = 2  |  Minor Version (uint16) = 4     |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  8 |                       Reserved1 (uint32) = 0                    |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 12 |                       Reserved2 (uint32) = 0                    |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 16 |                       SnapLen (uint32) = 1024                   |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    header = bytearray(24)

    struct.pack_into("I", header, 0, 0xA1B2C3D4)

    struct.pack_into("H", header, 4, 2)  # major version

    struct.pack_into("H", header, 6, 4)  # minor version

    struct.pack_into("I", header, 8, 0)  # reserved 1

    struct.pack_into("I", header, 12, 0)  # reserved 2

    struct.pack_into("I", header, 16, 1024)  # snaplen

    #      0-------------- 1---------------2---------------3--------------
    #      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 20 | FCS (4b)  |R|P| Reserved3 (10b) |  Link-layer type (uint16)     |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    struct.pack_into("H", header, 20, l2type)

    # need to do some bitmasking to add the additional info
    addl = 0x00  # 16 bits
    addl = addl | 0 << 0  # 10 bit reserved3
    addl = addl | 0 << 10  # P bit
    addl = addl | 0 << 11  # R bit
    addl = addl | 0 << 12  # 4 bit FCS Len
    struct.pack_into("H", header, 22, addl)

    return header


def make_packet(data: bytes):
    """Convert incoming data bytes to a pcap-style packet.
    Uses current system time for timestamps
    """
    #      0-------------- 1---------------2---------------3--------------
    #      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  0 |                    Timestamp (Seconds)                          |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  4 |                  Timestamp (Microseconds)                       |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  8 |                  Captured Packet Length                         |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 12 |                  Original Packet Length                         |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 16 /                                                                 /
    #    /                        Packet Data                              /
    #    /                variable length, not padded                      /
    #    /                                                                 /
    packet_header = bytearray(16)

    length = len(data)
    captured_length = min(length, 1024)

    # split apart seconds and microseconds
    seconds = int(time.time())
    microseconds = int((time.time() - seconds) * 1e6)

    struct.pack_into("I", packet_header, 0, seconds)  # timestamp
    struct.pack_into("I", packet_header, 4, microseconds)  # timestamp
    struct.pack_into("I", packet_header, 8, captured_length)  # truncated packet length
    struct.pack_into("I", packet_header, 12, length)  # original packet length

    return packet_header + data
