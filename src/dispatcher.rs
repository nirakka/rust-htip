use crate::htip::*;
use crate::*;
use std::collections::HashMap;

const TTC_OUI: &[u8; 3] = b"\xe0\x27\x1a";

type ParserCtor = fn() -> Box<dyn Parser>;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Hash)]
struct ParserKey {
    tlv_type: u8,
    prefix: Vec<u8>,
}

impl ParserKey {
    fn new(tlv_type: u8, prefix: Vec<u8>) -> Self {
        ParserKey { tlv_type, prefix }
    }
}

pub struct Dispatcher {
    registry: HashMap<ParserKey, ParserCtor>,
}

impl Dispatcher {
    fn register(&mut self, tlv_type: TlvType, key: Vec<u8>, ctor: fn() -> Box<dyn Parser>) {
        self.registry
            .insert(ParserKey::new(tlv_type.into(), key), ctor);
    }

    fn register_htip(&mut self, key: Vec<u8>, ctor: fn() -> Box<dyn Parser>) {
        let mut prefix = TTC_OUI.to_vec();
        prefix.extend(key);
        self.register(TlvType::Custom, prefix, ctor);
    }

    fn empty() -> Self {
        Dispatcher {
            registry: HashMap::new(),
        }
    }

    pub fn new() -> Self {
        let mut instance = Dispatcher::empty();
        //this is "whatever stated in the first byte (maximum length 255)"
        instance.register_htip(b"\x01\x01".to_vec(), || Box::new(SizedText::new(255)));
        //this should be "exact length 6"
        instance.register_htip(b"\x01\x02".to_vec(), || Box::new(SizedText::exact(6)));
        //this is "whatever stated in the first byte (maximum length 31)"
        instance.register_htip(b"\x01\x03".to_vec(), || Box::new(SizedText::new(31)));
        //TODO add the rest!
        //subtype1 info4
        //subtype1 info20
        instance.register_htip(b"\x01\x20".to_vec(), || Box::new(Percentage::new()));
        //subtype1 info21
        //subtype1 info22
        //subtype1 info23
        //subtype1 info24
        //subtype1 info25
        //subtype1 info26
        //subtype1 info27
        //subtype1 info50
        //subtype1 info51
        //subtype1 info52
        //subtype1 info53
        //subtype1 info54
        //subtype1 info80
        //TODO: use a composite parser for this in the future
        //ignore for now
        //subtype1 info255
        //TODO: subtype 2 with composite parser?
        //TODO: subtype 3 with mac parser?
        instance
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    //use crate::htip::*;

    #[test]
    fn api_test() {
        let mut dsp = Dispatcher::new();
        dsp.register_htip(b"\x01\x01".to_vec(), || Box::new(SizedText::new(255)));
    }
}
