use pcap::Device;
use std::env;

mod common;

fn main() -> Result<(), pcap::Error> {
    let args: Vec<String> = env::args().collect();

    //we don't have a specified network interface
    if args.len() != 2 {
        let device = Device::lookup()?;
        match pcap::Capture::from_device(device)?.open() {
            Ok(cap) => common::parse_captured(cap),
            Err(_err) => eprintln!(
                "device open error, requires root privilege\n\
                Usage: sudo {}\nerror: {}",
                &args[0], _err
            ),
        }
    // exactly two args from here on
    // help case
    } else if args[1] == "--help" {
        println!(
            "USAGE: sudo ./target/debug/online [interface_name]\n\
            if interface_name is empty the first available interface will be used."
        );
    //explicitly specified network interface in args[1]
    } else {
        match pcap::Capture::from_device(args[1].as_str())?.open() {
            Ok(cap) => common::parse_captured(cap),
            Err(err) => eprintln!(
                "device open error: {}\n\
                error: {}",
                &args[1], err
            ),
        }
    }
    Ok(())
}
