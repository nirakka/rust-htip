use crate::htip::*;
use crate::*;
use std::cmp::Ordering;
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
    parsers: HashMap<ParserKey, ParserCtor>,
    keys: Vec<ParserKey>,
}

impl Dispatcher {
    fn register(&mut self, tlv_type: TlvType, key: Vec<u8>, ctor: fn() -> Box<dyn Parser>) {
        let key = ParserKey::new(tlv_type.into(), key);
        self.parsers.insert(key.clone(), ctor);
        match self.keys.binary_search(&key) {
            Ok(index) => panic!("key already present at: {} , key:{:?}", index, key),
            Err(index) => self.keys.insert(index, key),
        }
    }

    fn register_htip(&mut self, key: Vec<u8>, ctor: fn() -> Box<dyn Parser>) {
        let mut prefix = TTC_OUI.to_vec();
        prefix.extend(key);
        self.register(TlvType::Custom, prefix, ctor);
    }

    fn empty() -> Self {
        Dispatcher {
            parsers: HashMap::new(),
            keys: Vec::new(),
        }
    }

    fn cmp_key_to_tlv(key_val: &Vec<u8>, tlv_val: &Vec<u8>) -> Ordering {
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

    fn parser_from_key(&self, key: ParserKey) -> Box<dyn Parser> {
        match self.parsers.get(&key) {
            Some(ctor) => ctor(),
            None => unimplemented!(),
        }
    }

    pub fn parse_tlv<'a>(&self, tlv: &'a TLV) -> Result<HtipData, HtipError<'a>> {
        let key = self.parser_key_from_tlv(&tlv).ok_or(HtipError::Unknown)?;
        let skip = key.prefix.len();
        let mut parser = self.parsers.get(&key).unwrap()();
        parser.parse(&tlv.value[skip..])?;
        Ok(parser.data())
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
        let mut dsp = Dispatcher::empty();
        dsp.register_htip(b"\x01\x01".to_vec(), || Box::new(SizedText::new(255)));
    }

    #[test]
    fn finds_key() {
        //type 127, length 16
        let frame = b"\xfe\x0f\xe0\x27\x1a\x01\x01\x09123456789\
            \xfe\x0c\xe0\x27\x1a\x01\x02\x06OUIOUI";
        let mut dsp = Dispatcher::new();
        //collect our two tlvs, and do stuff with them
        let tlvs = parse_frame(frame)
            .into_iter()
            .collect::<Result<Vec<TLV>, _>>()
            .unwrap();
        assert_eq!(tlvs.len(), 2);
        let key0 = dsp.parser_key_from_tlv(&tlvs[0]).unwrap();
        assert_eq!(key0.tlv_type, 127);
        assert_eq!(key0.prefix, b"\xe0\x27\x1a\x01\x01");

        let key1 = dsp.parser_key_from_tlv(&tlvs[1]).unwrap();
        assert_eq!(key1.tlv_type, 127);
        assert_eq!(key1.prefix, b"\xe0\x27\x1a\x01\x02");
    }

    #[test]
    fn find_key_is_none() {
        //unknown oui
        let frame = b"\xfe\x0f\xAA\xBB\x1a\x01\x01\x09123456789";
        let mut dsp = Dispatcher::new();
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
        dsp.register_htip(b"\x01\x01".to_vec(), || Box::new(SizedText::new(255)));
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
