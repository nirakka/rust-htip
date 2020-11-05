use pcap;
use pcap::Device;
use rust_htip;
use rust_htip::Dispatcher;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        let device = Device::lookup().unwrap();
        let cap = pcap::Capture::from_device(device).unwrap().open().unwrap();
        rust_htip::parse_captured(cap);
    } else {
        let device = &args[1];
        let cap = pcap::Capture::from_device(&device[..]).unwrap().open().unwrap();
        rust_htip::parse_captured(cap);
    }
}

