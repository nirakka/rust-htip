use rust_htip::{Dispatcher, InvalidFrame};

pub fn parse_captured<T: pcap::Activated>(mut capture: pcap::Capture<T>) {
    //static setup
    //1. setup our filter (broadcast + lldp)
    capture
        .filter("ether broadcast && ether proto 0x88cc")
        .expect("pcap: unable to set filter");
    //2. get a dispatcher instance
    let mut dispatcher = Dispatcher::new();

    loop {
        let cap_data = capture.next();
        match cap_data {
            Ok(data) => {
                //strip the ethernet header (14 bytes)
                if let Some(htip_frame) = data.get(14..) {
                    let parse_result = dispatcher.parse(htip_frame);
                    match parse_result {
                        Ok(data) => println!("{}\n", serde_json::to_string_pretty(&data).unwrap()),
                        Err(err) => handle_bad_frame(err, &mut dispatcher),
                    }
                }
            }
            //if calling next() causes an error (e.g. no more data), we bail
            Err(_) => break,
        }
    }
}

fn handle_bad_frame(frame: InvalidFrame, dispatcher: &mut Dispatcher) {
    println!("BAD FRAME! possibly incorrect parse results!\n");
    let stuff = frame.parse(dispatcher);
    println!("{}\n", serde_json::to_string_pretty(&stuff).unwrap());
}
