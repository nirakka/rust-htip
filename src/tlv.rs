use std::fmt;

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

impl<'a> TLV<'a> {
    pub fn new(ttype: TlvType, length: usize, value: &'a [u8]) -> TLV {
        TLV {
            ttype,
            length,
            value,
        }
    }

    pub fn tlv_type(&self) -> TlvType {
        self.ttype
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn value(&self) -> &'a [u8] {
        &self.value[..]
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Display for TLV<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.value.iter()
            .map(|x| format!("\\x{:02x}", x))
            .collect::<String>();
        write!(f, "type: {:?}, length: {}, value:{}", self.ttype, self.length, bytes)
    }
}
#[cfg(debug)]
mod tests {

    #[test]
    fn tlv_type_end_as_byte_is_zero() {
        assert_eq!(TlvType::End.as_byte(), 0);
    }

    #[test]
    fn tlv_type_chassis_id_as_byte_is_one() {
        assert_eq!(TlvType::ChassisID.as_byte(), 1);
    }

    #[test]
    fn tlv_from_byte_0_is_end_tlv() {
        assert_eq!(TlvType::from(0u8), TlvType::End);
    }

    #[test]
    fn tlv_from_byte_1_is_chassis_id() {
        assert_eq!(TlvType::from(1u8), TlvType::ChassisID);
    }

    #[test]
    fn tlv_from_byte_2_is_port_id() {
        assert_eq!(TlvType::from(2u8), TlvType::PortID);
    }

    #[test]
    fn tlv_from_byte_3_is_ttl() {
        assert_eq!(TlvType::from(3u8), TlvType::TimeToLive);
    }

    #[test]
    fn tlv_from_byte_9_to_126_is_reserved() {
        (9u8..126u8)
            .map(|u| (TlvType::from(u), TlvType::Reserved(u)))
            .for_each(|(u, reserved_u)| assert_eq!(u, reserved_u));
    }

    #[test]
    fn tlv_from_byte_127_is_custom() {
        assert_eq!(TlvType::from(127u8), TlvType::Custom);
    }

    #[test]
    fn tlv_from_byte_range_128_to_255_are_invalid() {
        (128u8..255u8)
            .map(|u| (TlvType::from(u), TlvType::Invalid(u)))
            .for_each(|(u, invalid_u)| assert_eq!(u, invalid_u));
    }

    #[test]
    fn tlv_from_and_then_as_bytes_gives_original_u8_range_0_255() {
        (0u8..255u8)
            .map(|u| (TlvType::from(u).as_byte(), u))
            .for_each(|(u, expected_u)| assert_eq!(u, expected_u));
    }
}
