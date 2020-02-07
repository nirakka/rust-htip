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

            _ => TlvType::End,
        }
    }
}

#[derive(Debug)]
pub struct TLV {
    ttype: TlvType,
    length: usize,
    //to create this value, make sure you copy/clone
    //the contents of the input slice
    value: Vec<u8>,
}

pub fn parse_tlv(input: &[u8]) -> Result<TLV, ParsingError> {
    if input.is_empty() {
        return Result::Err(ParsingError::Empty);
    }
    unimplemented!()

    //if input length less than 2
    //it's a too short error
    //
    //compute type
    //compute length
    //
    //if computed length > input length
    //this is a too short error
    //
    //return Ok tlv instance
    //TLV { length : ...
    //      type : ....
    //      //we have to clone the value
    //      value : ....
    //      }
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

impl TLV {
    pub fn get_type(&self) -> &TlvType {
        &self.ttype
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
