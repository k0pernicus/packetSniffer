# packetSniffer

# Author

k0pernicus  
antonin[dot]carette[at]gmail[dot]com

# Version

1.5

# Goal

A simple personal packet sniffer in Rust.  
This version only support wlp2s0 device(s)

# How to use it?

```
cargo build --release
cargo run -- -p (list devices to sniff)
cargo run -- -d <device_name_to_sniff>
```
