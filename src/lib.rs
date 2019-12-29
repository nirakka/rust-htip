#[derive(Debug, PartialEq, Eq)]
pub enum ParsingError {
    TooShort,
    TooLong,
    Empty,
}

#[derive(Debug, PartialEq, Eq)]
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
            _ => 0,
        }
        //unimplemented!();
    }
}

impl From<u8> for TlvType {
    fn from(byte: u8) -> Self {
        match byte {
            0u8 => TlvType::End,
            1u8 => TlvType::ChassisID,
            2u8 => TlvType::PortID,
            3u8 => TlvType::TimeToLive,
            9u8..=126u8 => TlvType::Reserved(byte),
            127u8 => TlvType::Custom,
            128u8..=255u8 => TlvType::Invalid(byte),

            _   => TlvType::End,

        }
    }
}

#[derive(Debug)]
pub struct TLV;

pub fn parseTLV(input : Vec<u8>) -> Result<TLV, ParsingError> {
    match input {
        unimplemented!();
}

impl TLV {
    pub fn get_type(&self) -> TlvType {
        unimplemented!();
    }

    pub fn len(&self) -> usize {
        unimplemented!();
    }

    pub fn value(&self) -> &Vec<u8> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
