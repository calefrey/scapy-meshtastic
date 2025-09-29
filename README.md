# scapy-meshtastic

A custom protocol decoder for [scapy](https://scapy.net/) that can handle [meshtastic](https://meshtastic.org/) packets

Uses the default channel key `AQ==` for decryption. Messages that cannot be decrypted raise an error and are ignored.

Designed to support packet captures performed by a (hackerpager)[https://www.hackerpager.net/] at this time

See `app.py` for example usage, and the scapy website for the features you can do with the decoded packets

This project has grown beyond the scapy parser and now supports the whole pipeline, from packet capture to post-processing

## Capturing Packets and Viewing in Wireshark

If you have a [CatWAN USB Stick](https://github.com/ElectronicCats/CatWAN_USB_Stick) you can turn it into a LoRa sniffer, and even generate pcap files for analysis in Wireshark.
See the `LoRaSniffer` folder for flashing instructions, and pair it with `pcap_writer.py` to generate either a pcap file or a stream of pcap data, which can be used with Wireshark.

To decode meshtastic packets in Wireshark you'll need to download the [dissector plugin](https://www.hackerpager.net/wireshark-plugin/) written for the [Hacker Pager](https://www.hackerpager.net/).

To use it live, pipe `pcap_writer.py` (outputting to stdout) into wireshark (capturing from stdin)
```
python pcap_writer.py -o - | wireshark.exe -k -i -
```

## Record and Analyze Packets

I wrote `record_packets.py` to analyze incoming meshtastic data from a pcap stream. It records the packets from a pcap file (or stream) into a database.
You could load multiple pcap files from e.g. different antenna sources into one database to see how your mesh is performing overall from multiple perspectives.

You can pair it directly with `pcap_writer.py` and a LoRa stick to get live updates to your database:
```
python pcap_writer.py -o - | python record_packets.py -
```

Note that none of these live capture/pipe examples will work in PowerShell because it won't pipe binary data. Use cmd if on windows.

Future plans:
- [ ] Support user-supplied channel keys to decode messages that use different keys
- [x] Find and document hardware/software for capturing and packets over the air
- [x] Add logging to a database for later analysis
- [ ] Integrate both the capture and logging parts into one script without needing to do piping
- [ ] Document some recommended SQL viewer queries for network analysis
