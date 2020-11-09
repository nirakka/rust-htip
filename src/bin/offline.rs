use std::env;
mod common;

//Accepts a number of file names
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    for arg in args {
        print!("opening file {} ...", arg);
        match pcap::Capture::from_file(arg) {
            Ok(capture) => {
                println!("OK");
                common::parse_captured(capture);
            }
            Err(err) => println!("FAILED! error: {}", err),
        }
    }
}
