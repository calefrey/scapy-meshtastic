# scapy-meshtastic

A custom protocol decoder for [scapy](https://scapy.net/) that can handle [meshtastic](https://meshtastic.org/) packets

Uses the default channel key `AQ==` for decryption. Messages that cannot be decrypted raise an error and are ignored.

Designed to support packet captures performed by a (hackerpager)[https://www.hackerpager.net/] at this time

See `app.py` for example usage, and the scapy website for the features you can do with the decoded packets

Future plans:
- [ ] Support user-supplied channel keys to decode messages that use different keys
- [ ] Find and document hardware/software for doing real-time sniffing, not just captures