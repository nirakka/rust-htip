use pcap;
use pcap::Device;
use rust_htip;
use std::env;

fn main() -> Result<(), pcap::Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        let device = Device::lookup()?;
        println!("{}", &args[0]);
        let cap = match pcap::Capture::from_device(device)?.open() {
            Ok(_cap) => _cap,
            Err(_err) => panic!(
                "device open error\nrequires root privilege or device not found Usage: sudo {}\nerror: {}",
                &args[0], _err
            ),
        };
        Ok(rust_htip::parse_captured(cap))
    } else if args[1] == "--help" {
        println!("USAGE: sudo ./target/debug/online [interface_name], if interface_name is empty the first available interface will be used.");
        Ok(())
    } else {
        let device = &args[1];
        let cap = match pcap::Capture::from_device(&device[..])?.open(){
            Ok(_cap) => _cap,
            Err(_err) => panic!(
                "device open error no such device: {}\nerror: {}",
                &args[1], _err
            ),

        };
        Ok(rust_htip::parse_captured(cap))
    }
}
