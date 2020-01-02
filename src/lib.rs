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
pub struct TLV {
    ttype: u8,
    length: usize,
    value: Vec<u8>,
}

pub fn parseTLV(input :  Vec<u8>) -> Result<TLV, ParsingError> {
    if input.is_empty() {
        return Result::Err(ParsingError::Empty);
    }
    match input.len() {
        1   => Result::Err(ParsingError::TooShort),
        2   => {
            if input[0] == b'0' && input[1] == b'0' {
                
                let _type = input[0] as char;
                let _type = _type.to_digit(10).unwrap() as u8;
                let tlv = TLV {
                    ttype: _type,
                    length: input.iter().count()-2,
                    value: vec![]
                };
                return Result::Ok(tlv);
            } else {
                return Result::Err(ParsingError::TooShort);
            }
        },
        514 => {
            if input.iter().skip(2).all(|&x| x == b'0') { 
            return Result::Ok(
                    TLV{
                        ttype: 1u8,
                        length: input.iter().count()-2,
                        value: vec![0;512]
                    }
                );
            } else { 
                let val = input.iter().cloned().skip(2).collect::<Vec<u8>>();
                Result::Ok(
                    TLV{
                        ttype: input[0],
                        length: input.iter().count()-2,
                        value: val, 
                    })
            } 

        },
        _   => {
                let val = input.iter().cloned().skip(2).collect::<Vec<u8>>();
                Result::Ok(
                TLV{
                    ttype: input[0],
                    length: input.iter().count()-2,
                    value: val, 
                })
            }
    }
}

impl TLV {
    pub fn get_type(&self) -> TlvType {
        TlvType::from(self.ttype)
    }

    pub fn len(&self) -> usize {
        self.length 
    }

    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
