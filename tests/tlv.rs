use rust_htip::*;

#[test]
fn parsing_empty_input_returns_empty_error() {
    let input = vec![];
    assert_eq!(parseTLV(input).err(), Some(ParsingError::Empty));
}

#[test]
fn parsing_1_byte_buffer_is_short() {
    let input = vec![b'1'];
    assert_eq!(
        parseTLV(input).expect_err("result is not ParsingError::TooShort"),
        ParsingError::TooShort
    );
}

#[test]
fn parsing_2_byte_buffer_with_no_value_is_short() {
    let input = vec![b'1', b'1'];
    assert_eq!(
        parseTLV(input).expect_err("result is not ParsingError::TooShort"),
        ParsingError::TooShort
    );
}

#[test]
fn parsing_2_byte_end_of_lldpdu_is_ok() {
    let input = vec![b'0', b'0'];
    if let Ok(tlv) = parseTLV(input) {
        assert_eq!(tlv.len(), 0);
        assert_eq!(tlv.get_type(), TlvType::End);
        assert_eq!(tlv.value(), &vec![]);
    } else {
        panic!("Parse result should be Ok(), with zero len, and zero value");
    }
}

#[test]
fn parsing_max_length_tlv_all_zeroes_and_type_is_chassis_id() {
    let mut input = vec![b'0'; 514];
    input[0] = 3u8;
    input[1] = 255u8;
    if let Ok(tlv) = parseTLV(input) {
        assert_eq!(tlv.len(), 512);
        assert_eq!(tlv.get_type(), TlvType::ChassisID);
        assert_eq!(*tlv.value(), vec![0u8; 512]);
    } else {
        panic!("Parse result should be Ok(), with 512 len and 512 value");
    }
}

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
