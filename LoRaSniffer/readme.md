# LoRaSniffer Firmware

Grab Meshtastic packets using a CatWAN radio, and write them to serial output

Build instructions:
1. Install the [PlatforIO](https://platformio.org/) ide or IDE/plugin
2. Build and upload (either with the extension buttons or `pio run -t upload`)

Usage:
- Plug the dongle in, and watch the LoRa packets roll in via a serial console
- Use my python script that wrangles the serial terminal and outputs pcap-formatted packets to stdout
- Pipe that stdout to wireshark or similar
- To decode other LoRa protocols or different meshtastic settings, make changes to the definitions at the top of the file