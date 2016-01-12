# packetSniffer

# Author

k0pernicus  
antonin[dot]carette[at]gmail[dot]com

# Version

1.5

# Goal

A simple personal packet sniffer in Rust.  
This software will save informations received in a .pcap file, in ```rslts``` directory.  
You can visualize these informations with ```tcpdump``` like ```tcpdump -qns 0 -A -r rslts.pcap```.

# How to use it?

```
cargo build --release
cargo run -- -p (list devices to sniff)
cargo run -- -d <device_name_to_sniff>
```
