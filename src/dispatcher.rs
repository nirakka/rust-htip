use crate::parsers::*;
use crate::*;
use std::cmp::Ordering;
use std::collections::HashMap;

const TTC_OUI: &[u8; 3] = b"\xe0\x27\x1a";

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
    //hash table with keys to parsers
    parsers: HashMap<ParserKey, Box<dyn Parser>>,
    //ordered array of parser keys
    keys: Vec<ParserKey>,
}

impl Dispatcher {
    fn register(&mut self, tlv_type: TlvType, key: Vec<u8>, parser: Box<dyn Parser>) {
        let key = ParserKey::new(tlv_type.into(), key);
        self.parsers.insert(key.clone(), parser);
        match self.keys.binary_search(&key) {
            Ok(index) => panic!("key already present at: {} , key:{:?}", index, key),
            Err(index) => self.keys.insert(index, key),
        }
    }

    fn register_htip(&mut self, key: Vec<u8>, parser: Box<dyn Parser>) {
        let mut prefix = TTC_OUI.to_vec();
        prefix.extend(key);
        self.register(TlvType::Custom, prefix, parser);
    }

    fn empty() -> Self {
        Dispatcher {
            parsers: HashMap::new(),
            keys: Vec::new(),
        }
    }

    fn cmp_key_to_tlv(key_val: &[u8], tlv_val: &[u8]) -> Ordering {
        let diff = key_val
            .iter()
            .zip(tlv_val)
            .map(|(a, b)| a.cmp(b))
            .find(|&cmp_res| cmp_res != Ordering::Equal);
        let key_is_shorter = key_val.len() <= tlv_val.len();

        match (diff, key_is_shorter) {
            (Some(cmp_res), _) => cmp_res,
            (None, true) => Ordering::Equal,
            (None, false) => Ordering::Greater,
        }
    }

    fn key_index_from_tlv(&self, tlv: &TLV) -> Option<usize> {
        self.keys
            .binary_search_by(|key| {
                //check type
                match key.tlv_type.cmp(&tlv.tlv_type().clone().into()) {
                    //type's the same, check contents
                    Ordering::Equal => Dispatcher::cmp_key_to_tlv(&key.prefix, tlv.value()),
                    other => other,
                }
            })
            .ok()
    }

    fn parser_key_from_tlv(&self, tlv: &TLV) -> Option<ParserKey> {
        self.key_index_from_tlv(tlv).map(|u| self.keys[u].clone())
    }

    fn parser_from_key(&mut self, key: ParserKey) -> &mut Box<dyn Parser> {
        match self.parsers.get_mut(&key) {
            Some(parser) => parser,
            None => unimplemented!(),
        }
    }

    pub fn parse_tlv<'a>(&mut self, tlv: &'a TLV) -> Result<ParseData, ParsingError<'a>> {
        let key = self
            .parser_key_from_tlv(&tlv)
            .ok_or(ParsingError::Unknown)?;

        let skip = key.prefix.len();

        let parser = self.parsers.get_mut(&key).unwrap();
        let mut context = Context::new(&tlv.value[skip..]);
        //TODO emit a warning somewhere if we have unconsumed data
        parser.parse(&mut context)
    }

    pub fn new() -> Self {
        let mut instance = Dispatcher::empty();
        instance.register(TlvType::from(1u8), b"".to_vec(), Box::new(TypedData::new()));
        instance.register(TlvType::from(2u8), b"".to_vec(), Box::new(TypedData::new()));
        instance.register(
            TlvType::from(3u8),
            b"".to_vec(),
            Box::new(Number::new(NumberSize::Two)),
        );
        //this is "whatever stated in the first byte (maximum length 255)"
        instance.register_htip(b"\x01\x01".to_vec(), Box::new(SizedText::new(255)));
        //this should be "exact length 6"
        instance.register_htip(b"\x01\x02".to_vec(), Box::new(SizedText::exact(6)));
        //this is "whatever stated in the first byte (maximum length 31)"
        instance.register_htip(b"\x01\x03".to_vec(), Box::new(SizedText::new(31)));
        //subtype1 info4
        instance.register_htip(b"\x01\x04".to_vec(), Box::new(SizedText::new(31)));
        //subtype1 info20
        instance.register_htip(b"\x01\x20".to_vec(), Box::new(Percentage::new()));
        //subtype1 info21
        instance.register_htip(b"\x01\x21".to_vec(), Box::new(Percentage::new()));
        //subtype1 info22
        instance.register_htip(b"\x01\x22".to_vec(), Box::new(Percentage::new()));
        //subtype1 info23
        instance.register_htip(
            b"\x01\x23".to_vec(),
            Box::new(SizedNumber::new(NumberSize::Six)),
        );
        //subtype1 info24
        instance.register_htip(
            b"\x01\x24".to_vec(),
            Box::new(SizedNumber::new(NumberSize::One)),
        );
        //subtype1 info25
        instance.register_htip(
            b"\x01\x25".to_vec(),
            Box::new(SizedNumber::new(NumberSize::One)),
        );
        //subtype1 info26
        instance.register_htip(
            b"\x01\x26".to_vec(),
            Box::new(SizedNumber::new(NumberSize::One)),
        );
        //subtype1 info27
        instance.register_htip(
            b"\x01\x27".to_vec(),
            Box::new(SizedNumber::new(NumberSize::One)),
        );
        //subtype1 info50
        instance.register_htip(b"\x01\x50".to_vec(), Box::new(SizedText::new(63)));
        //subtype1 info51
        instance.register_htip(b"\x01\x51".to_vec(), Box::new(Percentage::new()));
        //subtype1 info52
        instance.register_htip(b"\x01\x52".to_vec(), Box::new(Percentage::new()));
        //subtype1 info53
        instance.register_htip(b"\x01\x53".to_vec(), Box::new(Percentage::new()));
        //subtype1 info54
        instance.register_htip(b"\x01\x54".to_vec(), Box::new(Percentage::new()));
        //subtype1 info80
        instance.register_htip(
            b"\x01\x80".to_vec(),
            Box::new(SizedNumber::new(NumberSize::Two)),
        );
        //TODO: use a composite parser for this in the future
        //subtype1 info255
        //TODO: use composite parser for this
        //subtype 2
        instance.register_htip(b"\x03".to_vec(), Box::new(Mac::new()));

        instance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_test() {
        let mut dsp = Dispatcher::empty();
        dsp.register_htip(b"\x01\x01".to_vec(), Box::new(SizedText::new(255)));
    }

    #[test]
    fn finds_key() {
        //type 127, length 16
        let frame = b"\xfe\x0f\xe0\x27\x1a\x01\x01\x09123456789\
            \xfe\x0c\xe0\x27\x1a\x01\x02\x06OUIOUI\
            \x02\x0a0123456789";
        let dsp = Dispatcher::new();
        //collect our two tlvs, and do stuff with them
        let tlvs = parse_frame(frame)
            .into_iter()
            .collect::<Result<Vec<TLV>, _>>()
            .unwrap();
        assert_eq!(tlvs.len(), 3);
        let key0 = dsp.parser_key_from_tlv(&tlvs[0]).unwrap();
        assert_eq!(key0.tlv_type, 127);
        assert_eq!(key0.prefix, b"\xe0\x27\x1a\x01\x01");

        let key1 = dsp.parser_key_from_tlv(&tlvs[1]).unwrap();
        assert_eq!(key1.tlv_type, 127);
        assert_eq!(key1.prefix, b"\xe0\x27\x1a\x01\x02");

        let key2 = dsp.parser_key_from_tlv(&tlvs[2]).unwrap();
        assert_eq!(key2.tlv_type, 1);
        assert_eq!(key2.prefix, b"");
    }

    #[test]
    fn find_key_is_none() {
        //unknown oui
        let frame = b"\xfe\x0f\xAA\xBB\x1a\x01\x01\x09123456789";
        let dsp = Dispatcher::new();
        let tlvs = parse_frame(frame)
            .into_iter()
            .collect::<Result<Vec<TLV>, _>>()
            .unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(None, dsp.parser_key_from_tlv(&tlvs[0]));
    }

    #[test]
    #[should_panic]
    fn adding_key_twice_panics() {
        let mut dsp = Dispatcher::new();
        dsp.register_htip(b"\x01\x01".to_vec(), Box::new(SizedText::new(255)));
    }

    #[test]
    fn one_tlv_parse_succeeds() {
        let frame = b"\xfe\x0f\xe0\x27\x1a\x01\x01\x09123456789";
        let mut dsp = Dispatcher::new();
        //collect our two tlvs, and do stuff with them
        let tlvs = parse_frame(frame)
            .into_iter()
            .collect::<Result<Vec<TLV>, _>>()
            .unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(
            "123456789",
            dsp.parse_tlv(&tlvs[0]).unwrap().into_string().unwrap()
        );
    }

    #[test]
    fn simple_tlv_parse_succeeds() {
        let frame = b"\xfe\x0f\xe0\x27\x1a\x01\x01\x09123456789\
            \xfe\x0c\xe0\x27\x1a\x01\x02\x06OUIOUI";
        let mut dsp = Dispatcher::new();
        //collect our two tlvs, and do stuff with them
        let tlvs = parse_frame(frame)
            .into_iter()
            .collect::<Result<Vec<TLV>, _>>()
            .unwrap();
        assert_eq!(
            "123456789",
            dsp.parse_tlv(&tlvs[0]).unwrap().into_string().unwrap()
        );
        assert_eq!(
            "OUIOUI",
            dsp.parse_tlv(&tlvs[1]).unwrap().into_string().unwrap()
        );
    }
}
