//TODO fix this `use everything` going on here
use crate::linters::*;
use crate::parsers::*;
use crate::subkeys::*;
use crate::*;
use std::cmp::Ordering;
use std::fmt;

const TTC_OUI: &[u8; 3] = b"\xe0\x27\x1a";

/// Unique combination of a tlv type and a binary prefix. If a TLV
/// `matches` a parser key, the registered parser (if any) for that
/// key will be invoked.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Hash)]
pub struct ParserKey {
    /// type of tlv
    pub tlv_type: u8,
    /// binary prefix that matches the begining of the contents of
    /// the tlv
    pub prefix: Vec<u8>,
}

impl ParserKey {
    pub fn new(tlv_type: u8, prefix: Vec<u8>) -> Self {
        ParserKey { tlv_type, prefix }
    }

    pub fn htip(prefix: Vec<u8>) -> Self {
        let prefix = TTC_OUI
            .to_vec()
            .into_iter()
            .chain(prefix.into_iter())
            .collect();
        ParserKey {
            tlv_type: TlvType::Custom.into(),
            prefix,
        }
    }

    fn cmp_contents(key_val: &[u8], tlv_val: &[u8]) -> Ordering {
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
}

impl fmt::Display for ParserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Type:0x{:x} Prefix:0x{}",
            self.tlv_type,
            self.prefix
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>()
        )
    }
}

impl LexOrder<TLV<'_>> for ParserKey {
    fn lex_cmp(&self, other: &TLV<'_>) -> Ordering {
        match self.tlv_type.cmp(&other.tlv_type().into()) {
            Ordering::Equal => ParserKey::cmp_contents(&self.prefix, other.value()),
            other => other,
        }
    }
}

pub(crate) fn parse_as_tlv(input: &[u8]) -> Result<TLV, ParsingError> {
    //if input length less than 2
    //it's a too short error
    if input.len() < 2 {
        return Result::Err(ParsingError::TooShort);
    }

    //compute length
    let high_bit = ((input[0] as usize) & 0x1usize) << 8;
    let length = high_bit + (input[1] as usize);

    //check if lenght is too short
    if length + 2 > input.len() {
        return Result::Err(ParsingError::TooShort);
    }

    Result::Ok(TLV::new(
        //compute type
        TlvType::from(input[0] >> 1),
        length,
        &input[2..2 + length],
    ))
}

///Parse a frame into a list of tlvs, stop on error
///This will never return an empty vector, so it's safe to call last on it
pub(crate) fn parse_frame(frame: &[u8]) -> Result<Vec<TLV>, InvalidFrame> {
    let mut result = vec![];
    let mut input = frame;

    while !input.is_empty() {
        match parse_as_tlv(input) {
            Ok(tlv) => {
                //calculate the new input
                assert!(tlv.len() + 2 <= input.len());
                input = &input[(tlv.len() + 2)..];
                //save the tlv on the result vector
                result.push(tlv);
            }
            Err(_error) => {
                return Err(InvalidFrame {
                    tlvs: result,
                    pointer: input,
                })
            }
        }
    }
    Ok(result)
}

///The result in case of a frame that cannot be parsed. Such a frame had a section
///of data that could not be parsed as a valid TLV.
#[derive(Debug)]
pub struct InvalidFrame<'a> {
    ///The TLVs that were successfully parsed up until failure
    pub tlvs: Vec<TLV<'a>>,
    ///The actual data that cannot be parsed into a TLV. It is possible
    ///that this failure is a result of the last tlv that was parsed.
    ///This tlv is the last tlv in [InvalidFrame::tlvs].
    pub pointer: &'a [u8],
}

impl fmt::Display for InvalidFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.tlvs)
    }
}

impl<'a> InvalidFrame<'a> {
    pub fn parse(self, dispatcher: &mut Dispatcher) -> FrameInfo<'a> {
        let mut fi = dispatcher.parse_tlvs(self.tlvs);
        fi.errors.push((
            TlvKey::new(0, vec![]),
            ParsingError::InvalidFrame(self.pointer),
        ));
        fi
    }
}

pub struct Dispatcher<'a> {
    parsers: Storage<ParserKey, TLV<'a>, Box<dyn Parser>>,
    linters: Vec<Box<dyn Linter>>,
}

impl Default for Dispatcher<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispatcher<'_> {
    fn add_parser(&mut self, tlv_type: TlvType, key: Vec<u8>, parser: Box<dyn Parser>) {
        let key = ParserKey::new(tlv_type.into(), key);

        if self.parsers.insert(key, parser).is_some() {
            //Just panic here, we probably did a bad registration
            panic!("overwriting a parser!");
        }
    }

    fn add_htip_parser(&mut self, key: Vec<u8>, parser: Box<dyn Parser>) {
        let mut prefix = TTC_OUI.to_vec();
        prefix.extend(key);
        self.add_parser(TlvType::Custom, prefix, parser);
    }

    fn empty() -> Self {
        Dispatcher {
            parsers: Storage::new(),
            linters: vec![],
        }
    }

    pub(crate) fn parse_tlv<'a, 's>(
        &mut self,
        tlv: &'a TLV<'s>,
    ) -> (ParserKey, Result<ParseData, ParsingError<'s>>) {
        //get key
        match self.parsers.key_of(tlv) {
            //do we have a parser?
            Some(key) => {
                //skipping data related to the key
                let skip = key.prefix.len();
                let parser = self.parsers.get_mut(&key).unwrap();
                //setup context(take skip into account)
                let mut context = Context::new(&tlv.value()[skip..]);
                (key, parser.parse(&mut context))
            }
            None => {
                //we don't have a parser for this
                //use the default AnyBinary parser
                let mut context = Context::new(&tlv.value());
                (
                    //the fake key only stores the type; everything else is data
                    TlvKey::new(tlv.tlv_type().into(), vec![]),
                    (AnyBinary).parse(&mut context),
                )
            }
        }
    }

    pub(crate) fn parse_tlv_ex<'a, 's>(
        &mut self,
        tlv: &'a TLV<'s>,
        lints: &mut Vec<LintEntry>,
    ) -> (ParserKey, Result<ParseData, ParsingError<'s>>) {
        //get key
        match self.parsers.key_of(tlv) {
            //do we have a parser?
            Some(key) => {
                //skipping data related to the key
                let skip = key.prefix.len();
                let parser = self.parsers.get_mut(&key).unwrap();
                //setup context(take skip into account)
                let mut context = Context::new(&tlv.value()[skip..]);
                let res = (key.clone(), parser.parse(&mut context));
                //check if context is empty, else issue a lint
                if !context.get().is_empty() {
                    lints.push(
                        LintEntry::new(Lint::Warning(2))
                            .with_tlv(key)
                            .with_extra_info(format!("{} extra bytes", context.get().len())),
                    );
                }
                res
            }
            None => {
                //we don't have a parser for this
                //use the default AnyBinary parser
                let mut context = Context::new(&tlv.value());
                //the fake key only stores the type; everything else is data
                let key = TlvKey::new(tlv.tlv_type().into(), vec![]);
                //issue a lint for unhandled tlv
                lints.push(LintEntry::new(Lint::Warning(3)).with_tlv(key.clone()));
                //return the parsed thing
                (key, (AnyBinary).parse(&mut context))
            }
        }
    }

    pub(crate) fn lint(&self, info: &[InfoEntry]) -> Vec<LintEntry> {
        self.linters
            .iter()
            .flat_map(|linter| linter.lint(info))
            .collect()
    }

    /// Parses the given frame and returns relevant [FrameInfo]
    /// If the frame has misconstructed TLVs it returns an [InvalidFrame]
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_htip::Dispatcher;
    /// let data = b"\x02\x05ABCDE\x00\x00";
    ///
    /// let mut dispatcher = Dispatcher::new();
    /// let frame_info = dispatcher.parse(data).unwrap();
    /// println!("number of tlvs: {}", frame_info.tlvs.len());
    /// println!("number of infos: {}", frame_info.info.len());
    /// println!("number of parser errors: {}", frame_info.errors.len());
    /// println!("number of lints: {}", frame_info.lints.len());
    /// ```
    pub fn parse<'a>(&mut self, frame: &'a [u8]) -> Result<FrameInfo<'a>, InvalidFrame<'a>> {
        let tlvs = parse_frame(frame)?;
        Ok(self.parse_tlvs(tlvs))
    }

    fn parse_tlvs<'a>(&mut self, tlvs: Vec<TLV<'a>>) -> FrameInfo<'a> {
        //everything's fine, keep on parsing/linting
        let mut lints = vec![];
        let (info, errors) = tlvs
            .iter()
            .map(|tlv| self.parse_tlv_ex(tlv, &mut lints))
            //split into ok data and parsing errors
            .partition::<Vec<_>, _>(|(_tlv, res)| res.is_ok());
        //unwrap data
        let info = info
            .into_iter()
            .map(|(tlv, res)| (tlv, res.unwrap()))
            .collect::<Vec<_>>();
        //unwrap errors
        let errors = errors
            .into_iter()
            .map(|(tlv, err)| (tlv, err.unwrap_err()))
            .collect::<Vec<_>>();

        lints.append(&mut self.lint(&info));
        FrameInfo {
            tlvs,
            info,
            errors,
            lints,
        }
    }

    /// Create a new Dispatcher instance
    pub fn new() -> Self {
        let mut instance = Dispatcher::empty();
        instance.add_parser(TlvType::from(0u8), b"".to_vec(), Box::new(NoData));
        instance.add_parser(TlvType::from(1u8), b"".to_vec(), Box::new(TypedData::new()));
        instance.add_parser(TlvType::from(2u8), b"".to_vec(), Box::new(TypedData::new()));
        instance.add_parser(
            TlvType::from(3u8),
            b"".to_vec(),
            Box::new(Number::new(NumberSize::Two)),
        );
        instance.add_parser(
            TlvType::from(4u8),
            b"".to_vec(),
            //max sized text.. no formatting no nothing
            Box::new(Text::new(255)),
        );
        //this is "whatever stated in the first byte (maximum length 255)"
        instance.add_htip_parser(b"\x01\x01".to_vec(), Box::new(SizedText::new(255)));
        //this should be "exact length 6"
        instance.add_htip_parser(b"\x01\x02".to_vec(), Box::new(SizedText::exact(6)));
        //this is "whatever stated in the first byte (maximum length 31)"
        instance.add_htip_parser(b"\x01\x03".to_vec(), Box::new(SizedText::new(31)));
        //subtype1 info4
        instance.add_htip_parser(b"\x01\x04".to_vec(), Box::new(SizedText::new(31)));
        //subtype1 info20
        instance.add_htip_parser(b"\x01\x14".to_vec(), Box::new(Percentage::new()));
        //subtype1 info21
        instance.add_htip_parser(b"\x01\x15".to_vec(), Box::new(Percentage::new()));
        //subtype1 info22
        instance.add_htip_parser(b"\x01\x16".to_vec(), Box::new(Percentage::new()));
        //subtype1 info23
        instance.add_htip_parser(
            b"\x01\x17".to_vec(),
            Box::new(SizedNumber::new(NumberSize::Six)),
        );
        //subtype1 info24
        instance.add_htip_parser(
            b"\x01\x18".to_vec(),
            Box::new(SizedNumber::new(NumberSize::One)),
        );
        //subtype1 info25
        instance.add_htip_parser(
            b"\x01\x19".to_vec(),
            Box::new(SizedNumber::new(NumberSize::One)),
        );
        //subtype1 info26
        instance.add_htip_parser(
            b"\x01\x1a".to_vec(),
            Box::new(SizedNumber::new(NumberSize::One)),
        );
        //subtype1 info27
        instance.add_htip_parser(
            b"\x01\x1b".to_vec(),
            Box::new(SizedNumber::new(NumberSize::One)),
        );
        //subtype1 info50
        instance.add_htip_parser(b"\x01\x32".to_vec(), Box::new(SizedText::new(63)));
        //subtype1 info51
        instance.add_htip_parser(b"\x01\x33".to_vec(), Box::new(Percentage::new()));
        //subtype1 info52
        instance.add_htip_parser(b"\x01\x34".to_vec(), Box::new(Percentage::new()));
        //subtype1 info53
        instance.add_htip_parser(b"\x01\x35".to_vec(), Box::new(Percentage::new()));
        //subtype1 info54
        instance.add_htip_parser(b"\x01\x36".to_vec(), Box::new(Percentage::new()));
        //subtype1 info80
        instance.add_htip_parser(
            b"\x01\x50".to_vec(),
            Box::new(SizedNumber::new(NumberSize::Two)),
        );
        //TODO: use a composite parser for this in the future
        //subtype1 info255
        //subtype 2
        instance.add_htip_parser(b"\x02".to_vec(), Box::new(Connections::new()));
        instance.add_htip_parser(b"\x03".to_vec(), Box::new(Mac::new()));

        instance.linters.push(Box::new(CheckEndTlv));
        instance.linters.push(Box::new(InvalidChars::new()));
        instance.linters.push(Box::new(TLV1Linter));
        instance
    }
}
#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::ParsingError;

    #[test]
    fn parsing_empty_input_returns_too_short() {
        let input = &[];
        assert_eq!(parse_as_tlv(input).err(), Some(ParsingError::TooShort));
    }

    #[test]
    fn parsing_1_byte_buffer_is_short() {
        let input = &[b'1'];
        assert_eq!(
            parse_as_tlv(input).expect_err("result is not ParsingError::TooShort"),
            ParsingError::TooShort
        );
    }

    #[test]
    fn parsing_2_byte_buffer_with_no_value_is_short() {
        let input = &[1, 1];
        assert_eq!(
            parse_as_tlv(input).expect_err("result is not ParsingError::TooShort"),
            ParsingError::TooShort
        );
    }

    #[test]
    fn parsing_2_byte_end_of_lldpdu_is_ok() {
        let input = &[0, 0];
        if let Ok(tlv) = parse_as_tlv(input) {
            assert_eq!(tlv.len(), 0);
            assert_eq!(tlv.tlv_type(), TlvType::End);
            assert_eq!(tlv.value(), &[]);
        } else {
            panic!("Parse result should be Ok(), with zero len, and zero value");
        }
    }

    #[test]
    fn parsing_max_length_tlv_all_zeroes_and_type_is_chassis_id() {
        let input = &mut [0b0; 514];
        input[0] = 3u8;
        input[1] = 255u8;
        if let Ok(tlv) = parse_as_tlv(input) {
            assert_eq!(tlv.len(), 511);
            assert_eq!(tlv.tlv_type(), TlvType::ChassisID);
            assert_eq!(tlv.value(), vec![0u8; 511].as_slice());
        } else {
            panic!("Parse result should be Ok(), with 511 len and 511 value");
        }
    }

    #[test]
    fn parse_frame_with_one_tlv() {
        let frame = &[0, 0];
        let result = parse_frame(frame).unwrap();
        assert!(result.len() == 1, "result length is not 1");
        assert_eq!(result[0].tlv_type(), TlvType::End);
    }

    #[test]
    fn parse_frame_with_two_tlv() {
        let frame = &[2, 4, b'a', b'b', b'c', b'd', 0, 0];
        let mut result = parse_frame(frame).expect("this should parse cleanly!");
        assert_eq!(result.len(), 2);
        //end tlv here
        let tlv = result.pop().expect("end tlv should be here");
        assert_eq!(tlv.tlv_type(), TlvType::End);

        let tlv = result.pop().expect("chassis id tlv should be here");
        assert_eq!(tlv.tlv_type(), TlvType::ChassisID);
        let expected_value = b"abcd";
        assert_eq!(tlv.len(), expected_value.len());
        assert_eq!(tlv.value(), expected_value);
    }

    #[test]
    fn parse_frame_3tlvs_last_one_error() {
        let frame = b"\x02\x03123\x04\x0512345\x03\x1ftoo short";
        let mut invalid_frame = parse_frame(frame).unwrap_err();
        assert_eq!(invalid_frame.pointer, b"\x03\x1ftoo short");
        let second_tlv = invalid_frame.tlvs.pop().unwrap();
        assert_eq!(second_tlv.value(), b"12345");
        assert_eq!(second_tlv.len(), 5);
    }

    #[test]
    fn parse_frame_stops_parsing_after_error() {
        let frame = b"\x02\x03123\x04\x0512345\x03\x1ftoo short\x00\x00";
        let invalid_frame = parse_frame(frame).unwrap_err();
        assert_eq!(invalid_frame.pointer, b"\x03\x1ftoo short\x00\x00");
        assert_eq!(invalid_frame.tlvs.len(), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_test() {
        let mut dsp = Dispatcher::empty();
        dsp.add_htip_parser(b"\x01\x01".to_vec(), Box::new(SizedText::new(255)));
    }

    #[test]
    fn finds_key() {
        //type 127, length 16
        let frame = b"\xfe\x0f\xe0\x27\x1a\x01\x01\x09123456789\
            \xfe\x0c\xe0\x27\x1a\x01\x02\x06OUIOUI\
            \x02\x0a0123456789";
        let dsp = Dispatcher::new();
        //collect our two tlvs, and do stuff with them
        let tlvs = parse_frame(frame).unwrap();
        assert_eq!(tlvs.len(), 3);
        let key0 = dsp.parsers.key_of(&tlvs[0]).unwrap();
        assert_eq!(key0.tlv_type, 127);
        assert_eq!(key0.prefix, b"\xe0\x27\x1a\x01\x01");

        let key1 = dsp.parsers.key_of(&tlvs[1]).unwrap();
        assert_eq!(key1.tlv_type, 127);
        assert_eq!(key1.prefix, b"\xe0\x27\x1a\x01\x02");

        let key2 = dsp.parsers.key_of(&tlvs[2]).unwrap();
        assert_eq!(key2.tlv_type, 1);
        assert_eq!(key2.prefix, b"");
    }

    #[test]
    fn find_key_is_none() {
        //unknown oui
        let frame = b"\xfe\x0f\xAA\xBB\x1a\x01\x01\x09123456789";
        let dsp = Dispatcher::new();
        let tlvs = parse_frame(frame).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(None, dsp.parsers.key_of(&tlvs[0]));
    }

    #[test]
    #[should_panic]
    fn adding_key_twice_panics() {
        let mut dsp = Dispatcher::new();
        dsp.add_htip_parser(b"\x01\x01".to_vec(), Box::new(SizedText::new(255)));
    }

    #[test]
    fn one_tlv_parse_succeeds() {
        let frame = b"\xfe\x0f\xe0\x27\x1a\x01\x01\x09123456789";
        let mut dsp = Dispatcher::new();
        //collect our two tlvs, and do stuff with them
        let tlvs = parse_frame(frame).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(
            "123456789",
            dsp.parse_tlv(&tlvs[0]).1.unwrap().into_string().unwrap()
        );
    }

    #[test]
    fn simple_tlv_parse_succeeds() {
        let frame = b"\xfe\x0f\xe0\x27\x1a\x01\x01\x09123456789\
            \xfe\x0c\xe0\x27\x1a\x01\x02\x06OUIOUI";
        let mut dsp = Dispatcher::new();
        //collect our two tlvs, and do stuff with them
        let tlvs = parse_frame(frame).unwrap();
        assert_eq!(
            "123456789",
            dsp.parse_tlv(&tlvs[0]).1.unwrap().into_string().unwrap()
        );
        assert_eq!(
            "OUIOUI",
            dsp.parse_tlv(&tlvs[1]).1.unwrap().into_string().unwrap()
        );
    }

    #[test]
    fn parse_detects_trailing_characters() {
        let frame = b"\xfe\x19\xe0\x27\x1a\x01\x01\x09123456789characters\
            \xfe\x11\xe0\x27\x1a\x01\x02\x06CAFEBEextra\
            \x00\x00";
        let mut dsp = Dispatcher::new();
        let results = dsp.parse(frame).expect("this should parse, check frame!");
        //assert that we have no errors
        assert!(results.errors.is_empty());
        assert_eq!(results.lints[0].lint, Lint::Warning(2));
        assert_eq!(results.lints.len(), 2);
    }

    #[test]
    fn parse_detects_unknown_tlvs() {
        //\xf0 is unknown to us
        let frame = b"\xf0\x100123456789ABCDEF\
            \x00\x00";
        let mut dsp = Dispatcher::new();
        let results = dsp.parse(frame).expect("this should parse, check frame!");
        //assert that we have no errors
        assert!(results.errors.is_empty());
        assert_eq!(results.lints[0].lint, Lint::Warning(3));
        assert_eq!(results.lints.len(), 1);
        match &results.info[0].1 {
            ParseData::Binary(bin) => assert_eq!(bin, b"0123456789ABCDEF"),
            _ => panic!("this should be a string!"),
        }
    }
}
