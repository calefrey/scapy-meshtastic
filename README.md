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

See `sample-views.sql` for some sql commands that will create helpful node- and packet- views.

## Log to database and display in Wireshark simultaneously (as seen at JawnCon 0x2)
This works on a linux machine. I haven't investigated Windows alternatives yet.

```bash
# Since each pipe is FIFO both consumers can't share a pipe. So we'll create two.
mkfifo /tmp/pcap_pipe1 /tmp/pcap_pipe2
# Now we start our consumers, wireshark and record_packets
wireshark -k -i /tmp/pcap_pipe1 &
 # Couldn't get redirection to work on short notice so we're piping from cat. Oh well.
cat /tmp/pcap_pipe2 | python record_packets.py - &
# Now we create our source and pipe the output to tee - which goes to both outputs
python pcap_writer.py -p /dev/ttyACM0 -o - | tee /tmp/pcap_pipe1 > /tmp/pcap_pipe2 &
```
You can view the status of these tasks by running `jobs`, but it will only work for jobs in that terminal session.
Quit by `fg`ing each process and `Ctrl-C` them

To view the list of active nodes, sorted by most recent announcement time, I ran an sqlite query in a `watch` loop.

```bash
watch "sqlite3 database.db -readonly -header -markdown 'SELECT * from NodeView order by lastheard DESC'"
```

Note that none of these live capture/pipe examples will work in PowerShell because it won't pipe binary data. Use cmd if on windows.

Future plans:
- [x] Find and document hardware/software for capturing and packets over the air
- [x] Add logging to a database for later analysis
- [x] Document some recommended SQL viewer queries for network analysis
- [x] Support capture and decoding of MQTT packets with a demo
- [ ] Integrate both the capture and logging parts into one script without needing to do piping
