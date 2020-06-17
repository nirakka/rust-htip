//TODO figure out proper visibilities
pub mod dispatcher;
pub mod parsers;

#[derive(Debug, PartialEq, Eq)]
///These are the errors that a basic parser may produce.
///The slice represents the original data that caused
///the error.
pub enum ParsingError<'a> {
    ///Not enough data to parse
    TooShort,
    ///The actual length is different from what is expected
    UnexpectedLength(usize),
    ///A sequence of bytes is different from what it was expected
    NotEqual(&'a [u8]),
    ///An invalid percentage, outside the range of [0-100]
    InvalidPercentage(u8),
    ///The text is not valid utf8
    InvalidText(std::str::Utf8Error),
    ///Unknown type/subtype
    Unknown,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TlvType {
    End,
    ChassisID,
    PortID,
    TimeToLive,
    PortDescritpion,
    SystemName,
    SystemDescription,
    SystemCapabilities,
    ManagementAddress,
    Reserved(u8),
    Custom,
    Invalid(u8),
}

impl TlvType {
    pub fn as_byte(&self) -> u8 {
        match self {
            TlvType::End => 0,
            TlvType::ChassisID => 1,
            TlvType::PortID => 2,
            TlvType::TimeToLive => 3,
            TlvType::PortDescritpion => 4,
            TlvType::SystemName => 5,
            TlvType::SystemDescription => 6,
            TlvType::SystemCapabilities => 7,
            TlvType::ManagementAddress => 8,
            TlvType::Reserved(x) => *x,
            TlvType::Custom => 127,
            TlvType::Invalid(x) => *x,
        }
    }
}

impl From<u8> for TlvType {
    fn from(byte: u8) -> Self {
        match byte {
            0u8 => TlvType::End,
            1u8 => TlvType::ChassisID,
            2u8 => TlvType::PortID,
            3u8 => TlvType::TimeToLive,
            4u8 => TlvType::PortDescritpion,
            5u8 => TlvType::SystemName,
            6u8 => TlvType::SystemDescription,
            7u8 => TlvType::SystemCapabilities,
            8u8 => TlvType::ManagementAddress,
            9u8..=126u8 => TlvType::Reserved(byte),
            127u8 => TlvType::Custom,
            128u8..=255u8 => TlvType::Invalid(byte),
        }
    }
}

impl From<TlvType> for u8 {
    fn from(source: TlvType) -> u8 {
        source.as_byte()
    }
}

#[derive(Debug)]
pub struct TLV<'a> {
    ttype: TlvType,
    length: usize,
    value: &'a [u8],
}

impl TLV<'_> {
    pub fn tlv_type(&self) -> TlvType {
        self.ttype
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

pub fn parse_tlv(input: &[u8]) -> Result<TLV, ParsingError> {
    //if input length less than 2
    //it's a too short error
    if input.len() < 2 {
        return Result::Err(ParsingError::TooShort);
    }

    //compute length
    let high_bit = ((input[0] as usize) & 0x1usize) << 8;
    let length = high_bit + (input[1] as usize);

    //check if lenght is too short
    if length > input.len() {
        return Result::Err(ParsingError::TooShort);
    }

    Result::Ok(TLV {
        //compute type
        ttype: TlvType::from(input[0] >> 1),
        length,
        //we have to clone the value
        value: &input[2..2 + length],
    })
}

pub fn parse_frame(frame: &[u8]) -> Vec<Result<TLV, ParsingError>> {
    let mut result = vec![];
    let mut input = frame;

    while !input.is_empty() {
        match parse_tlv(input) {
            Ok(tlv) => {
                //calculate the new input
                assert!(tlv.length + 2 <= input.len());
                input = &input[(tlv.len() + 2)..];
                //save the tlv on the result vector
                result.push(Ok(tlv));
            }
            Err(error) => {
                //we encountered an error.
                //push the erroro in the result vector
                //break out of the parsing loop
                result.push(Err(error));
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
