use pcap;
use rust_htip;
use rust_htip::Dispatcher;

use std::env;
use std::error::Error;

//Accepts a number of file names
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    for arg in args {
        print!("opening file {} ...", arg);
        match pcap::Capture::from_file(arg) {
            Ok(capture) => {
                println!("OK");
                parse_captured(capture);
            }
            Err(err) => println!("FAILED! error: {}", err),
        }
    }

    Ok(())
}

//this can be used for both a file and a
//live capture...
//
//you will probably have to use functions such as next & filter
//and break the iteration when there are no more packets.
//
//if the packet is HTIP (Q: how can we tell if it is?)
//  then pass it to rust_htip::dispatcher::Dispatcher::parse_frame()
//
//for the time being, try to "print" the packet information
//(implement display for lib.rs::FrameInfo and all other
//necessary structures)
//
//See the documentation here:
//https://docs.rs/pcap/0.7.0/pcap/struct.Capture.html
fn parse_captured<T: pcap::Activated>(mut _capture: pcap::Capture<T>) {
    loop {
        let cap = _capture.next();
        match cap {
            Ok(data) => {
                if data.get(12..14).unwrap() == [136, 204] {
                    // check LLDP type
                    let mut dispatcher = Dispatcher::new();
                    let frame_info = dispatcher.parse(data.get(14..).unwrap());

                    match frame_info {
                        Ok(data) => println!("number of tlvs: {}", data.tlvs.len()),
                        Err(err) => {
                            println!("{}", err);
                        }
                    }
                }
            }
            Err(err) => break,
        }
    }
}
