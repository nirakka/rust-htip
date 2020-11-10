use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};

use macaddr::MacAddr6;

use super::ParsingError;

pub(crate) trait Parser {
    fn parse<'a, 's>(
        &mut self,
        context: &'a mut Context<'s>,
    ) -> Result<ParseData, ParsingError<'s>>;
}

pub(crate) struct Context<'a> {
    data: &'a [u8],
}

impl<'a> Context<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Context { data }
    }

    pub fn set(&mut self, data: &'a [u8]) {
        self.data = data;
    }

    pub fn get(&mut self) -> &'a [u8] {
        self.data
    }
}

#[derive(Debug, Clone)]
///An enum holding the various possible types of HTIP data.
pub enum ParseData {
    ///Represents a number of up to 4 bytes, as well as percentages.
    U32(u32),
    ///Rare type, currently used for a 6byte update interval
    U64(u64),
    ///Represents textual data
    Text(String),
    ///Represents various binary data
    Binary(Vec<u8>),
    ///Represents a list of mac addresses
    Mac(Vec<MacAddr6>),
    ///Subtype 2
    Connections(PerPortInfo),
    ///typed data
    TypedData(u8, Vec<u8>),
    ///No data (end tlv)
    Null,
}

#[derive(Debug)]
pub struct InvalidConversion(ParseData);

impl TryFrom<ParseData> for u32 {
    type Error = InvalidConversion;

    fn try_from(data: ParseData) -> Result<Self, Self::Error> {
        match data {
            ParseData::U32(value) => Ok(value),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<ParseData> for u64 {
    type Error = InvalidConversion;

    fn try_from(data: ParseData) -> Result<Self, Self::Error> {
        match data {
            ParseData::U64(value) => Ok(value),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<ParseData> for String {
    type Error = InvalidConversion;

    fn try_from(data: ParseData) -> Result<Self, Self::Error> {
        match data {
            ParseData::Text(value) => Ok(value),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<ParseData> for Vec<u8> {
    type Error = InvalidConversion;

    fn try_from(data: ParseData) -> Result<Self, Self::Error> {
        match data {
            ParseData::Binary(value) => Ok(value.to_vec()),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<ParseData> for Vec<MacAddr6> {
    type Error = InvalidConversion;

    fn try_from(data: ParseData) -> Result<Self, Self::Error> {
        match data {
            ParseData::Mac(macs) => Ok(macs),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<ParseData> for PerPortInfo {
    type Error = InvalidConversion;

    fn try_from(data: ParseData) -> Result<Self, Self::Error> {
        match data {
            ParseData::Connections(port_info) => Ok(port_info),
            _ => Err(InvalidConversion(data)),
        }
    }
}

///I am not sure about this API, but I'll try it out for now
impl ParseData {
    pub fn into_u32(self) -> Option<u32> {
        self.try_into().ok()
    }

    pub fn into_u64(self) -> Option<u64> {
        self.try_into().ok()
    }

    pub fn into_string(self) -> Option<String> {
        self.try_into().ok()
    }

    pub fn into_bytes(self) -> Option<Vec<u8>> {
        self.try_into().ok()
    }

    pub fn into_mac(self) -> Option<Vec<MacAddr6>> {
        self.try_into().ok()
    }
}

///use with the fixed-size number parser
#[derive(Clone, Copy, PartialOrd, PartialEq, Ord, Eq)]
pub enum NumberSize {
    One = 1,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
}

///A parser for numbers that declare their sizes, with a known max size in bytes.
pub(crate) struct SizedNumber {
    size: NumberSize,
}

impl SizedNumber {
    pub fn new(size: NumberSize) -> Self {
        SizedNumber { size }
    }

    fn check_length(
        expected: usize,
        actual: usize,
        remaining: usize,
    ) -> Result<(), ParsingError<'static>> {
        match (actual <= expected, remaining >= actual) {
            (true, true) => Ok(()),
            (true, false) => Err(ParsingError::TooShort),
            (false, _) => Err(ParsingError::UnexpectedLength(actual)),
        }
    }

    fn data(size: NumberSize, value: u64) -> ParseData {
        if size <= NumberSize::Four {
            ParseData::U32(value as u32)
        } else {
            ParseData::U64(value)
        }
    }
}

impl Parser for SizedNumber {
    fn parse<'a, 's>(
        &mut self,
        context: &'a mut Context<'s>,
    ) -> Result<ParseData, ParsingError<'s>> {
        let input = context.data;

        if input.is_empty() {
            return Err(ParsingError::TooShort);
        }

        //normal processing
        //consume the length
        let actual = input[0] as usize;
        //what if it declares zero length? that's probably wrong
        if actual == 0 {
            return Err(ParsingError::TooShort);
        };

        let input = &input[1..];
        //check actual, expected and remaining buffer lengths
        SizedNumber::check_length(self.size as usize, actual, input.len())?;
        //we have the size we expect, try to parse
        //this into a number
        let value = (0..actual).fold(0u64, |mut acc, index| {
            acc <<= 8;
            acc += input[index] as u64;
            acc
        });

        //consume the bytes we used so far
        context.set(&input[actual..]);
        Ok(SizedNumber::data(self.size, value))
    }
}

///A fake parser used in testing
pub(crate) struct Dummy(pub u32);

impl Parser for Dummy {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        ctx.set(&ctx.data[self.0 as usize..]);
        Ok(ParseData::U32(self.0))
    }
}

pub(crate) struct AnyBinary;

impl Parser for AnyBinary {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let data = &ctx.data[..];
        ctx.set(&ctx.data[..0]);
        Ok(ParseData::Binary(data.to_vec()))
    }
}

pub(crate) struct FixedSequence {
    key: Vec<u8>,
}

impl FixedSequence {
    pub fn new(key: Vec<u8>) -> Self {
        FixedSequence { key }
    }
}

impl Parser for FixedSequence {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let input = ctx.data;

        if input.len() < self.key.len() {
            return Err(ParsingError::TooShort);
        }

        for (i, j) in self.key.iter().enumerate() {
            if j != &input[i] {
                return Err(ParsingError::NotEqual(&input[..i + 1]));
            }
        }

        ctx.set(&input[self.key.len()..]);
        Ok(ParseData::Binary(self.key.clone()))
    }
}

pub(crate) struct Text {
    max_size: usize,
}

impl Text {
    pub fn new(max_size: u8) -> Self {
        Text {
            max_size: max_size as usize,
        }
    }
}

impl Parser for Text {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let input = ctx.data;

        if input.is_empty() {
            return Err(ParsingError::TooShort);
        }

        let result = if input.len() < self.max_size {
            String::from_utf8(input.to_vec())
        } else {
            String::from_utf8(input[..self.max_size].to_vec())
        };

        match result {
            Err(err) => Err(ParsingError::InvalidText(err.utf8_error())),
            Ok(text) => {
                ctx.set(&input[text.len()..]);
                Ok(ParseData::Text(text))
            }
        }
    }
}

pub(crate) struct SizedText {
    max_size: usize,
}

impl SizedText {
    pub fn new(max_size: usize) -> Self {
        SizedText { max_size }
    }

    pub fn exact(size: usize) -> ExactlySizedText {
        ExactlySizedText {
            inner: SizedText::new(size),
            exact_size: size,
        }
    }

    fn check_max_size<'a>(max: usize, actual: usize) -> Result<(), ParsingError<'a>> {
        if actual <= max {
            Ok(())
        } else {
            Err(ParsingError::UnexpectedLength(actual))
        }
    }

    fn check_input_size<'a>(needed: usize, input: &[u8]) -> Result<(), ParsingError<'a>> {
        if needed <= input.len() {
            Ok(())
        } else {
            Err(ParsingError::TooShort)
        }
    }
}

impl Parser for SizedText {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let input = ctx.data;
        //first byte is the declared length
        //check against maximum expected size & that we have enough input
        let text_size = *input.get(0).ok_or(ParsingError::TooShort)? as usize;
        SizedText::check_max_size(self.max_size, text_size)?;
        SizedText::check_input_size(text_size, &input[1..])?;

        //we have enough data. Try to parse a utf8-string
        //ignore the first byte
        let result = String::from_utf8(input[1..text_size + 1].to_vec());
        match result {
            Err(error) => Err(ParsingError::InvalidText(error.utf8_error())),
            Ok(text) => {
                //input = &mut input[text_size + 1..];
                ctx.set(&input[text_size + 1..]);
                Ok(ParseData::Text(text))
            }
        }
    }
}

pub(crate) struct ExactlySizedText {
    inner: SizedText,
    exact_size: usize,
}

impl ExactlySizedText {
    fn check_exact_size<'a>(expected: usize, actual: usize) -> Result<(), ParsingError<'a>> {
        if actual == expected {
            Ok(())
        } else {
            Err(ParsingError::UnexpectedLength(actual))
        }
    }
}

impl Parser for ExactlySizedText {
    fn parse<'a, 's>(&mut self, input: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        //check if the reported size is what we are expecting
        let text_size = *input.data.get(0).ok_or(ParsingError::TooShort)? as usize;
        ExactlySizedText::check_exact_size(self.exact_size, text_size)?;

        //proceed as per SizedText
        self.inner.parse(input)
    }
}

pub(crate) struct Percentage;

impl Percentage {
    pub fn new() -> Self {
        Percentage {}
    }
}

impl Parser for Percentage {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let input = ctx.data;
        if input.len() < 2 {
            return Err(ParsingError::TooShort);
        }

        let size = input[0] as usize;
        if size != 1 {
            return Err(ParsingError::UnexpectedLength(size));
        }

        let val = input[1];
        if val > 100 {
            Err(ParsingError::InvalidPercentage(val))
        } else {
            ctx.set(&input[size + 1..]);
            Ok(ParseData::U32(val as u32))
        }
    }
}

pub(crate) struct CompositeParser {
    parts: Vec<Box<dyn Parser>>,
}

impl CompositeParser {
    pub fn new() -> Self {
        CompositeParser { parts: vec![] }
    }

    pub fn with_part(mut self, part: Box<dyn Parser>) -> Self {
        self.parts.push(part);
        self
    }

    pub fn extractor<F>(self, func: F) -> CompositeParserComplete
    where
        F: 'static + Fn(&mut Vec<ParseData>) -> ParseData,
    {
        CompositeParserComplete {
            parts: self.parts,
            data: vec![],
            func: Box::new(func),
        }
    }
}

pub(crate) struct CompositeParserComplete {
    parts: Vec<Box<dyn Parser>>,
    data: Vec<ParseData>,
    func: Box<dyn Fn(&mut Vec<ParseData>) -> ParseData>,
}

impl Parser for CompositeParserComplete {
    fn parse<'a, 's>(&mut self, input: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        for parser in &mut self.parts {
            self.data.push(parser.parse(input)?);
        }
        Ok((self.func)(&mut self.data))
    }
}

pub(crate) struct Mac;

impl Mac {
    pub fn new() -> Self {
        Mac {}
    }
}

impl Parser for Mac {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let input = ctx.data;
        let num = *input.get(0).ok_or(ParsingError::TooShort)? as usize;
        let input = &input[1..];
        let end = num * 6;

        if input.len() < end {
            Err(ParsingError::TooShort)
        } else {
            let data = input[0..end]
                .chunks(6)
                .map(|chunk| MacAddr6::from(<[u8; 6]>::try_from(chunk).unwrap()))
                .collect();

            ctx.set(&input[num * 6..]);
            Ok(ParseData::Mac(data))
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerPortInfo {
    pub interface: u32,
    pub port: u32,
    pub macs: Vec<MacAddr6>,
}

pub struct Connections {
    inner: CompositeParserComplete,
}

impl Connections {
    pub fn new() -> Self {
        let comp = CompositeParser::new()
            .with_part(Box::new(SizedNumber::new(NumberSize::Four)))
            .with_part(Box::new(SizedNumber::new(NumberSize::Four)))
            .with_part(Box::new(Mac::new()))
            .extractor(|data| {
                let ppi = PerPortInfo {
                    macs: data.pop().unwrap().into_mac().unwrap(),
                    port: data.pop().unwrap().into_u32().unwrap(),
                    interface: data.pop().unwrap().into_u32().unwrap(),
                };

                ParseData::Connections(ppi)
            });

        Connections { inner: comp }
    }
}

impl Parser for Connections {
    fn parse<'a, 's>(&mut self, input: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        self.inner.parse(input)
    }
}

pub struct Number {
    expected_size: NumberSize,
}

impl Number {
    pub fn new(expected_size: NumberSize) -> Self {
        Number { expected_size }
    }

    fn check_length(&self, len: usize) -> Result<usize, ParsingError<'static>> {
        let self_size = self.expected_size as usize;
        match len.cmp(&self_size) {
            Ordering::Less => Err(ParsingError::TooShort),
            Ordering::Equal => Ok(len),
            Ordering::Greater => Err(ParsingError::UnexpectedLength(len)),
        }
    }
}

impl Parser for Number {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let input = ctx.data;
        let size = self.check_length(input.len())?;
        let value = (0..size).fold(0u64, |mut acc, index| {
            acc <<= 8;
            acc += input[index] as u64;
            acc
        });
        //consume data
        ctx.set(&input[size..]);
        Ok(ParseData::U64(value))
    }
}

pub struct TypedData;

impl TypedData {
    pub fn new() -> Self {
        TypedData {}
    }
}

impl Parser for TypedData {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let input = ctx.data;

        let t = input.get(0).ok_or(ParsingError::TooShort)?;
        let _ = input.get(1).ok_or(ParsingError::TooShort)?;

        //data is everything in the buffer
        let data = input[1..].to_vec();

        //consume everything
        ctx.set(&input[input.len()..]);
        Ok(ParseData::TypedData(*t, data))
    }
}

pub struct NoData;

impl Parser for NoData {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        if ctx.data.is_empty() {
            Ok(ParseData::Null)
        } else {
            Err(ParsingError::UnexpectedLength(ctx.data.len()))
        }
    }
}

#[cfg(test)]
mod scratch {
    use super::*;

    #[test]
    fn api_test() {
        let mut comp = CompositeParser::new()
            .with_part(Box::new(Percentage::new()))
            .with_part(Box::new(FixedSequence::new(b"abc".to_vec())))
            .with_part(Box::new(FixedSequence::new(b"abc".to_vec())))
            .with_part(Box::new(Percentage::new()))
            .extractor(|data| data.pop().unwrap());

        let mut context = Context::new(b"\x01\x02abcabc\x01\x32");
        let result = comp.parse(&mut context);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap().into_u32().unwrap(), 0x32);
        assert_eq!(comp.parts.len(), 4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_forwards_buffer_and_returns_value() {
        let mut context = Context::new(b"\x00\x01\x02");
        let mut dummy = Dummy(2);
        let result = dummy.parse(&mut context).unwrap();

        assert_eq!(context.data.len(), 1);
        assert_eq!(context.data[0], 0x02);
        assert_eq!(result.into_u32(), Some(2));
    }

    #[test]
    fn number_parses_1byte_value() {
        //let input = vec![0x01, 0xff, 0x3c];
        let mut ctx = Context::new(b"\x01\xff\x3c");
        let mut parser = SizedNumber::new(NumberSize::One);
        //let remainder = parser.parse(&input).unwrap();
        let result = parser.parse(&mut ctx).unwrap();
        assert_eq!(result.into_u32(), Some(255));

        //consumed 2 bytes? unchanged remainder?
        assert_eq!(ctx.data.len(), 1);
        assert_eq!(ctx.data[0], 0x3c);
    }

    #[test]
    fn number_parses_2byte_value() {
        let mut ctx = Context::new(b"\x02\x02\x0a");
        let mut parser = SizedNumber::new(NumberSize::Two);
        let result = parser.parse(&mut ctx).unwrap();

        assert_eq!(ctx.data.len(), 0);
        assert_eq!(result.into_u32(), Some(522));
    }

    #[test]
    fn number_parses_4byte_value() {
        let mut ctx = Context::new(b"\x04\xff\xff\xff\xfe");
        let mut parser = SizedNumber::new(NumberSize::Four);
        let result = parser.parse(&mut ctx).unwrap();

        assert_eq!(ctx.data.len(), 0);
        assert_eq!(result.into_u32(), Some(u32::max_value() - 1));
    }

    #[test]
    fn number_fails_with_invalid_length() {
        let mut ctx = Context::new(b"\x0a\x02\x0a");
        let mut parser = SizedNumber::new(NumberSize::Two);
        let result = parser.parse(&mut ctx).err();

        assert_eq!(result, Some(ParsingError::UnexpectedLength(10)));
    }

    #[test]
    fn number_fails_for_short_input() {
        let mut ctx = Context::new(b"");
        let mut parser = SizedNumber::new(NumberSize::One);
        assert_eq!(parser.parse(&mut ctx).err(), Some(ParsingError::TooShort));

        let mut ctx = Context::new(b"\x01");
        let mut parser = SizedNumber::new(NumberSize::One);
        assert_eq!(parser.parse(&mut ctx).err(), Some(ParsingError::TooShort));
    }

    #[test]
    fn number_parse_fails_for_short_buffer() {
        //we're expecting 4 bytes, only 3 are present...
        let mut ctx = Context::new(b"\x04\x00\x00\x00");
        let mut parser = SizedNumber::new(NumberSize::Four);
        assert_eq!(parser.parse(&mut ctx).err(), Some(ParsingError::TooShort));
    }

    #[test]
    fn number_parse_succeeds_for_less_than_expected_size_u64() {
        //we're expecting up to 6bytes, input declares 2 bytes
        let mut ctx = Context::new(b"\x02\x01\xFFR");
        let mut parser = SizedNumber::new(NumberSize::Six);
        let result = parser.parse(&mut ctx).expect("should not fail");
        assert_eq!(result.into_u64().unwrap(), 511u64);
        //we consumed only the first 3 bytes, the 'R' must still be in its place
        assert_eq!(ctx.data[0], b'R');
    }

    #[test]
    fn number_parse_succeeds_for_less_than_expected_size_u32() {
        //we're expecting up to 4bytes, input declares 2 bytes
        let mut ctx = Context::new(b"\x02\x01\xFFR");
        let mut parser = SizedNumber::new(NumberSize::Four);
        let result = parser.parse(&mut ctx).expect("should not fail");
        //we consumed only the first 3 bytes, the 'R' must still be in its place
        assert_eq!(ctx.data[0], b'R');
        assert_eq!(result.into_u32().unwrap(), 511u32);
    }

    #[test]
    fn number_parse_fails_zero_size_number() {
        let mut ctx = Context::new(b"\x00");
        let mut parser = SizedNumber::new(NumberSize::One);
        let result = parser.parse(&mut ctx);

        assert_eq!(result.unwrap_err(), ParsingError::TooShort);
    }

    #[test]
    fn multiple_parsers_succeed() {
        let mut parsers: Vec<Box<dyn Parser>> = vec![
            Box::new(SizedNumber::new(NumberSize::One)),
            Box::new(Dummy(2)),
            Box::new(SizedNumber::new(NumberSize::Four)),
        ];
        let mut ctx = Context::new(b"\x01\x0A\xFF\xFF\x04\xFF\xFF\xFE\x00");

        let result: Result<Vec<ParseData>, ParsingError> = parsers
            .iter_mut()
            .map(|parser| parser.parse(&mut ctx))
            .collect();

        let data = result.unwrap();
        //is result exhausted?
        assert_eq!(ctx.data.len(), 0);
        //test parser results?
        assert_eq!(data[0].clone().into_u32(), Some(10));
        assert_eq!(data[1].clone().into_u32(), Some(2));
        assert_eq!(data[2].clone().into_u32(), Some(u32::max_value() - 511));
    }

    #[test]
    fn fixed_sequence_matches_and_consumes_buffer() {
        let mut ctx = Context::new(b"12345");
        let mut parser = FixedSequence::new(ctx.data.to_vec());
        let result = parser.parse(&mut ctx).unwrap();

        //has the slice been advanced?
        assert!(ctx.data.is_empty());

        let data_vec: Vec<u8> = result.try_into().unwrap();
        let data_string = String::from_utf8(data_vec).unwrap();
        assert_eq!(data_string, "12345");
    }

    #[test]
    fn fixed_sequence_fails_short_buffer() {
        let mut ctx = Context::new(b"\x01\x02");
        let mut parser = FixedSequence::new(b"\x01\x02\x03".to_vec());
        let result = parser.parse(&mut ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParsingError::TooShort);
    }

    #[test]
    fn fixed_sequence_does_not_match() {
        let original = vec![0x01, 0x02, 0x03, 0x04];
        let mut altered = original.clone();
        //change the copy a bit
        altered[2] = 0x04;
        altered.pop();
        let mut parser = FixedSequence::new(altered);
        let result = parser.parse(&mut Context::new(&original));
        assert!(result.is_err());

        let error = result.unwrap_err();
        //show where the first error occured
        assert_eq!(error, ParsingError::NotEqual(&original[..3]));
    }

    #[test]
    fn fixed_sequence_matches_with_longer_input() {
        let original = vec![0xff; 512];
        let altered = original[2..].to_owned();
        let mut parser = FixedSequence::new(altered);
        let mut ctx = Context::new(&original);
        let result = parser.parse(&mut ctx);
        assert!(result.is_ok());

        //two bytes should still be remaining
        assert_eq!(ctx.data.len(), 2);
    }

    #[test]
    fn percentage_is_valid_max_and_advances() {
        let mut ctx = Context::new(b"\x01\x64\xff\xff");
        let mut parser = Percentage::new();
        let result = parser.parse(&mut ctx);

        let remainder = &ctx.data;
        assert_eq!(remainder.len(), 2);
        assert_eq!(remainder, &b"\xff\xff");

        assert_eq!(result.unwrap().into_u32(), Some(100u32));
    }

    #[test]
    fn percentage_is_valid_min() {
        let mut ctx = Context::new(b"\x01\x00");
        let mut parser = Percentage::new();
        let result = parser.parse(&mut ctx);
        assert!(result.is_ok());

        assert_eq!(ctx.data.len(), 0);

        assert_eq!(result.unwrap().into_u32(), Some(0u32));
    }

    #[test]
    fn percentage_is_valid() {
        let mut ctx = Context::new(b"\x01\x32\x00");
        let mut parser = Percentage::new();
        let result = parser.parse(&mut ctx).unwrap();
        assert_eq!(result.into_u32().unwrap(), 50u32);
    }

    #[test]
    fn percentage_is_invalid() {
        let mut ctx = Context::new(b"\x01\x80");
        let mut parser = Percentage::new();
        let result = parser.parse(&mut ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParsingError::InvalidPercentage(128));
    }

    #[test]
    fn percentage_invalid_length() {
        let mut ctx = Context::new(b"\xab\x80");
        let mut parser = Percentage::new();
        let result = parser.parse(&mut ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParsingError::UnexpectedLength(0xab));
    }

    #[test]
    fn percentage_input_too_short() {
        let mut ctx = Context::new(b"\x01");
        let mut parser = Percentage::new();
        let result = parser.parse(&mut ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParsingError::TooShort);
    }

    #[test]
    fn text_input_too_short_when_empty() {
        let mut ctx = Context::new(b"");
        assert_eq!(
            Text::new(2).parse(&mut ctx).unwrap_err(),
            ParsingError::TooShort
        );
    }

    #[test]
    fn text_is_1_byte_string_and_advances() {
        let mut ctx = Context::new(b"ab");
        let mut parser = Text::new(1);
        let result = parser.parse(&mut ctx);
        assert!(result.is_ok());

        let remainder = ctx.data;
        assert_eq!(remainder.len(), 1);
        assert_eq!(remainder[0], b'b');

        let data = result.unwrap().into_string().unwrap();
        assert_eq!(data, String::from("a"));
    }

    #[test]
    fn text_fails_invalid_utf8() {
        let mut ctx = Context::new(b"\xff\x00\xff\xff\xff\xff\xff\xff");
        let mut parser = Text::new(8);
        let result = parser.parse(&mut ctx);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParsingError::InvalidText(_) => (),
            _ => panic!("text parse result should be a std::str::Utf8Error"),
        }
    }

    #[test]
    fn text_valid_string_less_than_max_size() {
        let mut ctx = Context::new(b"this is a valid string");
        let mut parser = Text::new(255);
        let result = parser.parse(&mut ctx);

        assert!(result.is_ok());
        assert_eq!(ctx.data.len(), 0);

        assert_eq!(
            result.unwrap().into_string().unwrap(),
            String::from("this is a valid string")
        );
    }

    #[test]
    fn text_includes_last_character() {
        let mut ctx = Context::new(b"abcd");
        let mut parser = Text::new(4);
        let result = parser.parse(&mut ctx).unwrap();
        assert_eq!(result.into_string().unwrap(), String::from("abcd"));
    }

    #[test]
    fn parse_one_mac_ok() {
        let mut ctx = Context::new(b"\x01\x0A\x0B\x0C\x0D\x0E\x0F");
        let mut parser = Mac::new();
        let result = parser.parse(&mut ctx).unwrap();
        //consumed everything?
        assert_eq!(ctx.data.len(), 0);

        let macs = result.into_mac().unwrap();
        //1 mac, equal to the one in the begining
        assert_eq!(macs.len(), 1);
        assert_eq!(macs[0], MacAddr6::new(0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F));
    }

    #[test]
    fn empty_mac_fails() {
        let mut ctx = Context::new(b"");
        let mut parser = Mac::new();
        let result = parser.parse(&mut ctx).unwrap_err();
        assert_eq!(result, ParsingError::TooShort);
    }

    #[test]
    fn short_mac() {
        let mut ctx = Context::new(b"\x01\x0A\x0B\x0C\x0D\x0E");
        let mut parser = Mac::new();
        let result = parser.parse(&mut ctx);
        assert_eq!(result.unwrap_err(), ParsingError::TooShort);
    }

    #[test]
    fn parse_three_macs_with_remainder() {
        let mut ctx = Context::new(b"\x03ABCDEF123456\xFF\xFF\xFF\xFF\xFF\xFFremainder");
        let mut parser = Mac::new();
        let result = parser.parse(&mut ctx).unwrap();
        assert_eq!(ctx.data, b"remainder");

        let macs = result.into_mac().unwrap();

        assert_eq!(macs[0].as_ref(), b"ABCDEF");
        assert_eq!(macs[1].as_ref(), b"123456");
        assert!(macs[2].is_broadcast());
    }

    #[test]
    fn less_mac_input_than_specified() {
        //specifies 3 macs, but it's one byte short
        let mut ctx = Context::new(b"\x03ABCDEF123456short");
        let mut parser = Mac::new();
        assert_eq!(parser.parse(&mut ctx).unwrap_err(), ParsingError::TooShort);
    }

    #[test]
    fn sized_text_input_too_short_when_empty() {
        let mut ctx = Context::new(b"");
        assert_eq!(
            SizedText::new(2).parse(&mut ctx).unwrap_err(),
            ParsingError::TooShort
        );
    }

    #[test]
    fn sized_text_input_less_than_expected_length() {
        let mut ctx = Context::new(b"\x06aaaa");
        assert_eq!(
            SizedText::new(255).parse(&mut ctx).unwrap_err(),
            ParsingError::TooShort
        );
    }

    #[test]
    fn sized_text_input_exceeds_max_size() {
        let mut ctx = Context::new(b"\x04abcd");
        let result = SizedText::new(3).parse(&mut ctx).unwrap_err();
        assert_eq!(result, ParsingError::UnexpectedLength(4));
    }

    #[test]
    fn sized_text_valid_string_less_than_max_size_and_consume_input() {
        let mut ctx = Context::new(b"\x04abcdefg");
        let mut parser = SizedText::new(255);
        let result = parser.parse(&mut ctx).unwrap();
        assert_eq!(result.into_string().unwrap(), String::from("abcd"));

        let remainder = ctx.data;
        assert_eq!(remainder.len(), 3);
        assert_eq!(remainder, String::from("efg").as_bytes());
    }

    #[test]
    fn sized_text_fails_invalid_utf8() {
        let mut invalid_input = Context::new(b"\x08\xff\x00\xff\xff\xff\xff\xff\xff");
        let mut parser = SizedText::new(8);
        let result = parser.parse(&mut invalid_input);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParsingError::InvalidText(_) => (),
            _ => panic!("text parse result should be a std::str::Utf8Error"),
        }
    }

    #[test]
    fn sized_text_zero_length_data_suceeds_with_empty() {
        let mut input = Context::new(b"\x00");
        let mut parser = SizedText::new(8);
        let result = parser.parse(&mut input).unwrap();
        assert_eq!(result.into_string().unwrap(), "");
    }

    #[test]
    fn exactly_sized_text_input_too_short_when_empty() {
        let mut input = Context::new(b"");
        assert_eq!(
            SizedText::exact(0).parse(&mut input).unwrap_err(),
            ParsingError::TooShort
        );
    }

    #[test]
    fn exactly_sized_text_input_exceeds_max_size() {
        let mut input = Context::new(b"\x04abcd");
        let result = SizedText::exact(3).parse(&mut input).unwrap_err();
        assert_eq!(result, ParsingError::UnexpectedLength(4));
    }

    #[test]
    fn exactly_sized_text_input_less_than_expected_length() {
        let mut input = Context::new(b"\x04abcd");
        let result = SizedText::exact(5).parse(&mut input).unwrap_err();
        assert_eq!(result, ParsingError::UnexpectedLength(4));
    }

    #[test]
    fn exactly_sized_text_valid_string_and_consumes_input() {
        let mut ctx = Context::new(b"\x04abcd");
        let mut parser = SizedText::exact(4);
        let result = parser.parse(&mut ctx).unwrap();
        assert_eq!(result.into_string().unwrap(), String::from("abcd"));
        assert_eq!(ctx.data.len(), 0);
    }

    #[test]
    fn exactly_sized_text_fails_invalid_utf8() {
        let mut invalid_input = Context::new(b"\x08\xff\x00\xff\xff\xff\xff\xff\xff");
        let mut parser = SizedText::exact(8);
        let result = parser.parse(&mut invalid_input);
        match result.unwrap_err() {
            ParsingError::InvalidText(_) => (),
            _ => panic!("text parse result should be a std::str::Utf8Error"),
        }
    }

    #[test]
    fn subtype2_parser_succeeds() {
        let mut ctx = Context::new(b"\x01\x07\x01\x02\x02ABCDEF123456");
        let mut parser = Connections::new();
        let result = parser.parse(&mut ctx).unwrap();
        let port_info: PerPortInfo = result.try_into().unwrap();
        assert_eq!(port_info.interface, 7);
        assert_eq!(port_info.port, 2);
        assert_eq!(port_info.macs.len(), 2);
        assert_eq!(port_info.macs[0].as_bytes(), b"ABCDEF");
        assert_eq!(port_info.macs[1].as_bytes(), b"123456");
    }

    #[test]
    fn subtype2_parser_fails_zero_size_number() {
        let mut input = Context::new(b"\x00\x07\x01\x02\x02ABCDEF123456");
        //--error here -------------^^^
        let mut parser = Connections::new();
        let result = parser.parse(&mut input);
        assert_eq!(result.unwrap_err(), ParsingError::TooShort);
    }

    #[test]
    fn subtype2_parser_fails_short_mac_data() {
        let input = b"\x01\x07\x01\x02\x02ABCDEF12345";
        //--error here, too short mac ---------------^
        let mut ctx = Context::new(input);
        let mut parser = Connections::new();
        let result = parser.parse(&mut ctx);
        assert_eq!(result.unwrap_err(), ParsingError::TooShort);
    }

    #[test]
    fn subtype2_parser_succeeds_with_correct_remainder() {
        let input = b"\x01\x03\x01\x09\x01BADFADremainder";
        //--remainder --------------------------^
        let mut ctx = Context::new(input);
        let mut parser = Connections::new();
        let result = parser.parse(&mut ctx).unwrap();
        let port_info: PerPortInfo = result.try_into().unwrap();
        assert_eq!(port_info.interface, 3);
        assert_eq!(port_info.port, 9);
        assert_eq!(port_info.macs.len(), 1);
        assert_eq!(port_info.macs[0].as_bytes(), b"BADFAD");
        assert_eq!(ctx.data, b"remainder");
    }

    #[test]
    fn subtype2_parser_fails_when_empty_buffer() {
        let mut ctx = Context::new(b"");
        let mut parser = Connections::new();
        assert_eq!(parser.parse(&mut ctx).unwrap_err(), ParsingError::TooShort);
    }

    #[test]
    fn subtype2_parses_long_numbers_and_zero_mac() {
        let mut ctx = Context::new(b"\x02\x01\xff\x04\x00\x00\x00\x01\x00remainder");
        let mut parser = Connections::new();
        let ppi: PerPortInfo = parser.parse(&mut ctx).unwrap().try_into().unwrap();
        assert_eq!(ppi.interface, 511);
        assert_eq!(ppi.port, 1);
        assert_eq!(ppi.macs.len(), 0);
    }

    #[test]
    fn typed_data_succeeds_and_consumes_minimum_data() {
        let mut ctx = Context::new(b"\xff\x00");
        let mut parser = TypedData::new();
        let result = parser.parse(&mut ctx).unwrap();

        //consumed data?
        assert_eq!(ctx.data.len(), 0);
        //is data what we expect?
        if let ParseData::TypedData(t, data) = result {
            assert_eq!(t, 255);
            assert_eq!(data, b"\x00");
        } else {
            panic!("expecting ParseData::TypedData, got something else!");
        }
    }

    #[test]
    fn typed_data_succeeds_and_consumes_arbitrary_data() {
        let mut ctx = Context::new(b"\x0aThe quick brown fox jumps over the lazy dog");
        let mut parser = TypedData::new();
        let result = parser.parse(&mut ctx).unwrap();

        //consumed all data?
        assert_eq!(ctx.data.len(), 0);
        //is data what we expect?
        if let ParseData::TypedData(t, data) = result {
            assert_eq!(t, 10);
            assert_eq!(
                std::str::from_utf8(&data).unwrap(),
                "The quick brown fox jumps over the lazy dog"
            );
        } else {
            panic!("expecting ParseData::TypedData, got something else!");
        }
    }

    #[test]
    fn typed_data_returns_too_short_on_empty() {
        let mut ctx = Context::new(b"");
        let mut parser = TypedData::new();
        let result = parser.parse(&mut ctx).unwrap_err();
        assert_eq!(result, ParsingError::TooShort);
    }

    #[test]
    fn typed_data_returns_too_short_on_one_byte() {
        let mut ctx = Context::new(b"\xff");
        let mut parser = TypedData::new();
        let result = parser.parse(&mut ctx).unwrap_err();
        assert_eq!(result, ParsingError::TooShort);
    }

    #[test]
    fn number_returns_too_short_on_empty() {
        let mut ctx = Context::new(b"");
        let mut parser = Number::new(NumberSize::Two);
        let result = parser.parse(&mut ctx).unwrap_err();
        assert_eq!(result, ParsingError::TooShort);
    }

    #[test]
    fn number_returns_too_short_on_less_than_expected_size() {
        let mut ctx = Context::new(b"\xff");
        let mut parser = Number::new(NumberSize::Two);
        let result = parser.parse(&mut ctx).unwrap_err();
        assert_eq!(result, ParsingError::TooShort);
    }

    #[test]
    fn number_returns_unexpected_length_error_on_over_expected_size() {
        let mut ctx = Context::new(b"\xff\x01\x02");
        let mut parser = Number::new(NumberSize::Two);
        let result = parser.parse(&mut ctx).unwrap_err();
        assert_eq!(result, ParsingError::UnexpectedLength(ctx.data.len()));
    }

    #[test]
    fn number_succeeds_and_consumes_buffer() {
        let mut ctx = Context::new(b"\xff\xff");
        let mut parser = Number::new(NumberSize::Two);
        let result = parser.parse(&mut ctx).unwrap();

        // consumed data?
        assert_eq!(ctx.data.len(), 0);

        if let ParseData::U64(r) = result {
            assert_eq!(r, 65535);
        } else {
            panic!("expecting ParseData::U64, got something else!");
        }
    }
}
