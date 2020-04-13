use std::convert::{TryFrom, TryInto};

#[derive(Debug, PartialEq, Eq)]
pub enum HtipError<'a> {
    TooShort,
    UnexpectedLength(usize),
    NotEqual(&'a [u8]),
    NotANumber(&'a [u8]),
    InvalidPercentage(&'a [u8]),
    InvalidMac(&'a [u8]),
}

pub enum HtipData {
    U32(u32),
    U64(u64),
    Text(String),
    Binary(Vec<u8>),
}

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
}

pub trait Parser {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError>;
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
pub struct Number {
    size: NumberSize,
    value: u32,
}

impl Number {
    pub fn new(size: NumberSize) -> Self {
        Number { size, value: 0 }
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

impl Parser for Number {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError> {
        if input.is_empty() {
            return Err(HtipError::TooShort);
        }

        //normal processing
        //consume the length
        let actual = input[0] as usize;
        let input = &input[1..];
        //check actual, expected and remaining buffer lengths
        Number::check_length(self.size as usize, actual, input.len())?;
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
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError> {
        Ok(&input[(self.0 as usize)..])
    }

    fn data(&self) -> HtipData {
        HtipData::U32(self.0)
    }
}

struct Fixed {
    key: Vec<u8>,
    //add other things if you think you need them
}

impl Fixed {
    pub fn new(key: Vec<u8>) -> Self {
        Fixed { key }
    }
}

impl Parser for Fixed {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError> {
        unimplemented!()
    }

    //return an HtipData::Binary
    fn data(&self) -> HtipData {
        unimplemented!()
    }
}

struct Text {
    //add your implementation here
}

impl Parser for Text {
    fn parse<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], HtipError> {
        unimplemented!()
    }

    //you return a String in the HtipData, copy/clone that
    fn data(&self) -> HtipData {
        unimplemented!()
    }
}
