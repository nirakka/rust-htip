use super::ParsingError;
use macaddr::MacAddr6;
use std::convert::{TryFrom, TryInto};

pub trait Parser {
    fn parse<'a, 's>(
        &mut self,
        context: &'a mut Context<'s>,
    ) -> Result<ParseData, ParsingError<'s>>;
}

pub struct Context<'a> {
    data: &'a [u8],
}

impl<'a> Context<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Context { data }
    }

    pub fn set(&mut self, data: &'a [u8]) {
        self.data = data;
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
}

///A parser for numbers of fixed size, up to four bytes
pub struct SizedNumber {
    size: NumberSize,
    value: u64,
}

impl SizedNumber {
    pub fn new(size: NumberSize) -> Self {
        SizedNumber { size, value: 0 }
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

    fn data(&self) -> ParseData {
        if self.size <= NumberSize::Four {
            ParseData::U32(self.value as u32)
        } else {
            ParseData::U64(self.value)
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
        self.value = (0..actual).fold(0u64, |mut acc, index| {
            acc <<= 8;
            acc += input[index] as u64;
            acc
        });

        //consume the bytes we used so far
        context.set(&input[actual..]);
        Ok(self.data())
    }
}

///A fake parser used in testing
pub struct Dummy(pub u32);

impl Parser for Dummy {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        ctx.set(&ctx.data[self.0 as usize..]);
        Ok(ParseData::U32(self.0))
    }
}

pub struct FixedSequence {
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

pub struct Text {
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
                Ok(ParseData::Text(text.clone()))
            }
        }
    }
}

pub struct SizedText {
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
                Ok(ParseData::Text(text.clone()))
            }
        }
    }
}

pub struct ExactlySizedText {
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

pub struct Percentage;

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

pub struct CompositeParser {
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
        F: 'static + Fn(&CompositeParserComplete) -> ParseData,
    {
        CompositeParserComplete {
            parts: self.parts,
            data: vec![],
            func: Box::new(func),
        }
    }
}

pub struct CompositeParserComplete {
    parts: Vec<Box<dyn Parser>>,
    data: Vec<ParseData>,
    func: Box<dyn Fn(&CompositeParserComplete) -> ParseData>,
}

impl Parser for CompositeParserComplete {
    fn parse<'a, 's>(&mut self, input: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        for parser in &mut self.parts {
            self.data.push(parser.parse(input)?);
        }
        Ok((self.func)(&self))
    }
}

pub struct Mac;

impl Mac {
    pub fn new() -> Self {
        Mac {}
    }
}

impl Parser for Mac {
    fn parse<'a, 's>(&mut self, ctx: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        let input = ctx.data;
        //TODO wtf? check for zero-sized input?
        let num = input[0] as usize;
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
        //setup the inner composite parser here
        //you need 3 parts, 2 sized numbers(1), and 1 mac
        // + the extractor, to generate a subtype 2 struct
        unimplemented!()
    }
}

impl Parser for Connections {
    fn parse<'a, 's>(&mut self, input: &'a mut Context<'s>) -> Result<ParseData, ParsingError<'s>> {
        //call the composite parsers's parse
        unimplemented!()
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
            .extractor(|cp| cp.parts.last().unwrap().data());

        //.add(Box::new(SizedNumber::new(NumberSize::Two)));
        let pr = comp.parse(b"\x01\x02abcabc\x01\x32");
        assert_eq!(comp.data().into_u32().unwrap(), 0x32);
        //let pr = comp.parse(b"abcabc\x02\x01\x01");
        print!("parse result: {:?}", pr);
        assert_eq!(comp.parts.len(), 4);
        let res = comp.data;
        assert_eq!(res.len(), 4);
    }
}
