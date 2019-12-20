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
        unimplemented!();
    }
}

impl From<u8> for TlvType {
    fn from(byte: u8) -> Self {
        unimplemented!();
    }
}

#[derive(Debug)]
pub struct TLV;

pub fn parseTLV(input : Vec<u8>) -> Result<TLV, ParsingError> {
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
