import argparse
import datetime
import sys

import serial
import serial.tools.list_ports

import pcap_utils

parser = argparse.ArgumentParser(
    description="Reads LoRa Packets from a LoRa Sniffer. Can generate wireshark-compatible pcap packets."
)
parser.add_argument(
    "-p", "--port", help="Specify serial port to use. By default will use the first."
)
parser.add_argument(
    "-o",
    "--out",
    dest="outfile",
    help="Specify the output file location. Defaults to timestamped pcap files. Supports '-' for stdout.",
)

args = parser.parse_args()

# handle outputs
if args.outfile == "-":  # want stdout
    outfile = None
    stdout = True
elif args.outfile:
    outfile = args.outfile
    stdout = False
else:
    outfile = f"output-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap"
    stdout = False


ser = serial.Serial()

# get the list of all serial ports
ports = serial.tools.list_ports.comports()
available_ports = [port for (port, desc, hwid) in ports]

if args.port:
    ser.port = args.port
else:
    if available_ports:
        # grab the first port and hope for the best
        ser.port = available_ports[0]
    else:  # no serial ports
        print("No serial devices connected")
        exit(1)

try:
    ser.open()
except serial.serialutil.SerialException:
    print(f"Could not open serial port {ser.port}")
    print(f"Available ports: {', '.join(available_ports)}")
    print("Specify the desired port with -p")
    exit(1)

# write the header to the output file or stdout
header = pcap_utils.make_header(l2type=270)  # LoRaTap is link-layer type 270
if stdout:
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.flush()
else:
    open(outfile, "wb").write(header)

# now we wait for incoming packets
while True:
    try:
        data = ser.read_until(b"\xcf\xcf")  # custom EOF bytes, must match arduino code
        data = data[:-2]  # remove EOF bytes
        packet = pcap_utils.make_packet(data)
        if stdout:
            sys.stdout.buffer.write(packet)
            sys.stdout.buffer.flush()
        else:
            open(outfile, "ab").write(packet)
    except KeyboardInterrupt:
        print("\nexiting")
        ser.close()
        exit()
