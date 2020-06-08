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
        //subtype1 info4
        instance.register_htip(b"\x01\x04".to_vec(), || Box::new(SizedText::new(31)));
        //subtype1 info20
        instance.register_htip(b"\x01\x20".to_vec(), || Box::new(Percentage::new()));
        //subtype1 info21
        instance.register_htip(b"\x01\x21".to_vec(), || Box::new(Percentage::new()));
        //subtype1 info22
        instance.register_htip(b"\x01\x22".to_vec(), || Box::new(Percentage::new()));
        //subtype1 info23
        instance.register_htip(b"\x01\x23".to_vec(), || {
            Box::new(SizedNumber::new(NumberSize::Six))
        });
        //subtype1 info24
        instance.register_htip(b"\x01\x24".to_vec(), || {
            Box::new(SizedNumber::new(NumberSize::One))
        });
        //subtype1 info25
        instance.register_htip(b"\x01\x25".to_vec(), || {
            Box::new(SizedNumber::new(NumberSize::One))
        });
        //subtype1 info26
        instance.register_htip(b"\x01\x26".to_vec(), || {
            Box::new(SizedNumber::new(NumberSize::One))
        });
        //subtype1 info27
        instance.register_htip(b"\x01\x27".to_vec(), || {
            Box::new(SizedNumber::new(NumberSize::One))
        });
        //subtype1 info50
        instance.register_htip(b"\x01\x50".to_vec(), || Box::new(SizedText::new(63)));
        //subtype1 info51
        instance.register_htip(b"\x01\x51".to_vec(), || Box::new(Percentage::new()));
        //subtype1 info52
        instance.register_htip(b"\x01\x52".to_vec(), || Box::new(Percentage::new()));
        //subtype1 info53
        instance.register_htip(b"\x01\x53".to_vec(), || Box::new(Percentage::new()));
        //subtype1 info54
        instance.register_htip(b"\x01\x54".to_vec(), || Box::new(Percentage::new()));
        //subtype1 info80
        instance.register_htip(b"\x01\x80".to_vec(), || {
            Box::new(SizedNumber::new(NumberSize::Two))
        });
        //TODO: use a composite parser for this in the future
        //subtype1 info255
        //TODO: use composite parser for this
        //subtype 2
        instance.register_htip(b"\x03".to_vec(), || Box::new(Mac::new()));

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
