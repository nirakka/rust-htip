#![allow(deprecated)]
use macaddr::MacAddr6;
use std::convert::{TryFrom, TryInto};

#[derive(Debug, PartialEq, Eq)]
///These are the errors that a basic parser may produce.
///The slice represents the original data that caused
///the error.
pub enum HtipError<'a> {
    ///Not enough data to parse
    TooShort,
    ///The actual length is different from what is expected
    UnexpectedLength(usize),
    ///A sequence of bytes is different from what it was expected
    NotEqual(&'a [u8]),
    ///An invalid percentage, outside the range of [0-100]
    InvalidPercentage(u8),
    ///The input data does not represent a valid MAC address
    #[deprecated = "reason: all 6-byte slices are valid macs"]
    InvalidMac(&'a [u8]),
    ///The text length is not utf8
    InvalidText(std::str::Utf8Error),
}

#[derive(Debug, Clone)]
///An enum holding the various possible types of HTIP data.
pub enum HtipData {
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
}

#[derive(Debug)]
pub struct InvalidConversion(HtipData);

impl TryFrom<HtipData> for u32 {
    type Error = InvalidConversion;

    fn try_from(data: HtipData) -> Result<Self, Self::Error> {
        match data {
            HtipData::U32(value) => Ok(value),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<HtipData> for u64 {
    type Error = InvalidConversion;

    fn try_from(data: HtipData) -> Result<Self, Self::Error> {
        match data {
            HtipData::U64(value) => Ok(value),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<HtipData> for String {
    type Error = InvalidConversion;

    fn try_from(data: HtipData) -> Result<Self, Self::Error> {
        match data {
            HtipData::Text(value) => Ok(value),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<HtipData> for Vec<u8> {
    type Error = InvalidConversion;

    fn try_from(data: HtipData) -> Result<Self, Self::Error> {
        match data {
            HtipData::Binary(value) => Ok(value.to_vec()),
            _ => Err(InvalidConversion(data)),
        }
    }
}

impl TryFrom<HtipData> for Vec<MacAddr6> {
    type Error = InvalidConversion;

    fn try_from(data: HtipData) -> Result<Self, Self::Error> {
        match data {
            HtipData::Mac(macs) => Ok(macs),
            _ => Err(InvalidConversion(data)),
        }
    }
}

///I am not sure about this API, but I'll try it out for now
impl HtipData {
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

pub trait Parser {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>>;
    fn data(&self) -> HtipData;
}

///use with the fixed-size number parser
#[derive(Clone, Copy)]
pub enum NumberSize {
    One = 1,
    Two,
    Three,
    Four,
}

///A parser for numbers of fixed size, up to four bytes
pub struct SizedNumber {
    size: NumberSize,
    value: u32,
}

impl SizedNumber {
    pub fn new(size: NumberSize) -> Self {
        SizedNumber { size, value: 0 }
    }

    fn check_length(
        expected: usize,
        actual: usize,
        remaining: usize,
    ) -> Result<(), HtipError<'static>> {
        match (actual == expected, remaining >= expected) {
            (true, true) => Ok(()),
            (true, false) => Err(HtipError::TooShort),
            (false, _) => Err(HtipError::UnexpectedLength(actual)),
        }
    }
}

impl Parser for SizedNumber {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        if input.is_empty() {
            return Err(HtipError::TooShort);
        }

        //normal processing
        //consume the length
        let actual = input[0] as usize;
        let input = &input[1..];
        //check actual, expected and remaining buffer lengths
        SizedNumber::check_length(self.size as usize, actual, input.len())?;
        //we have the size we expect, try to parse
        //this into a number
        self.value = (0..actual).fold(0u32, |mut acc, index| {
            acc <<= 8;
            acc += input[index] as u32;
            acc
        });
        //consume the bytes we used so far
        Ok(&input[actual..])
    }

    fn data(&self) -> HtipData {
        HtipData::U32(self.value)
    }
}

///A fake parser used in testing
pub struct Dummy(pub u32);

impl Parser for Dummy {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        Ok(&input[(self.0 as usize)..])
    }

    fn data(&self) -> HtipData {
        HtipData::U32(self.0)
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
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        if input.len() < self.key.len() {
            return Err(HtipError::TooShort);
        }

        for (i, j) in self.key.iter().enumerate() {
            if j != &input[i] {
                return Err(HtipError::NotEqual(&input[..i + 1]));
            }
        }

        Ok(&input[self.key.len()..])
    }

    fn data(&self) -> HtipData {
        HtipData::Binary(self.key.clone())
    }
}

#[deprecated = "reason: design does not match the 1-byte-length-contents-later common case"]
pub struct Text {
    max_size: usize,
    text: String,
}

impl Text {
    pub fn new(max_size: u8) -> Self {
        Text {
            max_size: max_size as usize,
            text: "".to_string(),
        }
    }
}

impl Parser for Text {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        if input.is_empty() {
            return Err(HtipError::TooShort);
        }

        let result = if input.len() < self.max_size {
            String::from_utf8(input.to_vec())
        } else {
            String::from_utf8(input[..self.max_size].to_vec())
        };

        match result {
            Err(err) => Err(HtipError::InvalidText(err.utf8_error())),
            Ok(text) => {
                self.text = text;
                Ok(&input[self.text.len()..])
            }
        }
    }

    fn data(&self) -> HtipData {
        HtipData::Text(self.text.clone())
    }
}

pub struct SizedText {
    text: String,
    max_size: usize,
}

impl SizedText {
    pub fn new(max_size: usize) -> Self {
        SizedText {
            text: String::from(""),
            max_size,
        }
    }

    pub fn exact(size: usize) -> ExactlySizedText {
        ExactlySizedText {
            inner: SizedText::new(size),
            exact_size: size,
        }
    }

    fn check_max_size<'a>(max: usize, actual: usize) -> Result<(), HtipError<'a>> {
        if actual <= max {
            Ok(())
        } else {
            Err(HtipError::UnexpectedLength(actual))
        }
    }

    fn check_input_size<'a>(needed: usize, input: &[u8]) -> Result<(), HtipError<'a>> {
        if needed <= input.len() {
            Ok(())
        } else {
            Err(HtipError::TooShort)
        }
    }
}

impl Parser for SizedText {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        //first byte is the declared length
        //check against maximum expected size & that we have enough input
        let text_size = *input.get(0).ok_or(HtipError::TooShort)? as usize;
        SizedText::check_max_size(self.max_size, text_size)?;
        SizedText::check_input_size(text_size, &input[1..])?;

        //we have enough data. Try to parse a utf8-string
        //ignore the first byte
        let result = String::from_utf8(input[1..text_size + 1].to_vec());
        match result {
            Err(error) => Err(HtipError::InvalidText(error.utf8_error())),
            Ok(text) => {
                self.text = text;
                Ok(&input[text_size + 1..])
            }
        }
    }

    fn data(&self) -> HtipData {
        HtipData::Text(self.text.clone())
    }
}

pub struct ExactlySizedText {
    inner: SizedText,
    exact_size: usize,
}

impl ExactlySizedText {
    fn check_exact_size<'a>(expected: usize, actual: usize) -> Result<(), HtipError<'a>> {
        if actual == expected {
            Ok(())
        } else {
            Err(HtipError::UnexpectedLength(actual))
        }
    }
}

impl Parser for ExactlySizedText {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        //check if the reported size is what we are expecting
        let text_size = *input.get(0).ok_or(HtipError::TooShort)? as usize;
        ExactlySizedText::check_exact_size(self.exact_size, text_size)?;

        //proceed as per SizedText
        self.inner.parse(input)
    }

    fn data(&self) -> HtipData {
        self.inner.data()
    }
}

pub struct Percentage {
    value: u8,
}

impl Percentage {
    pub fn new() -> Self {
        Percentage { value: 0u8 }
    }
}

impl Parser for Percentage {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        if input.len() < 2 {
            return Err(HtipError::TooShort);
        }

        let size = input[0] as usize;

        if size != 1 {
            return Err(HtipError::UnexpectedLength(size));
        }

        let val = input[1];

        if val > 100 {
            Err(HtipError::InvalidPercentage(val))
        } else {
            self.value = input[size];
            Ok(&input[size + 1..])
        }
    }

    fn data(&self) -> HtipData {
        HtipData::U32(self.value as u32)
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
        F: 'static + Fn(&CompositeParserComplete) -> HtipData,
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
    data: Vec<HtipData>,
    func: Box<dyn Fn(&CompositeParserComplete) -> HtipData>,
}

impl Parser for CompositeParserComplete {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        let mut remaining = input;
        for parser in &mut self.parts {
            remaining = parser.parse(remaining)?;
            self.data.push(parser.data());
        }
        Ok(remaining)
    }

    fn data(&self) -> HtipData {
        (self.func)(&self)
    }
}

pub struct Mac {
    data: Vec<MacAddr6>,
}

impl Mac {
    pub fn new() -> Self {
        Mac { data: vec![] }
    }
}

impl Parser for Mac {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError<'a>> {
        let num = input[0] as usize;
        let input = &input[1..];
        let end = num * 6;

        if input.len() < end {
            Err(HtipError::TooShort)
        } else {
            self.data = input[0..end]
                .chunks(6)
                .map(|chunk| {
                    MacAddr6::from(<[u8; 6]>::try_from(chunk).unwrap())
                })
                .collect();

            Ok(&input[num * 6..])
        }
    }

    fn data(&self) -> HtipData {
        HtipData::Mac(self.data.clone())
    }
}

#[cfg(test)]
mod tests {
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
