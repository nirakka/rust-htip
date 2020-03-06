use rust_htip::*;

#[test]
fn parse_frame_with_one_tlv() {
    let frame = &[0, 0];
    let result = parse_frame(frame);
    assert!(result.len() == 1, "result length is not 1");
    let res_tlv = result[0]
        .as_ref()
        .expect("an end tlv should be present here");
    assert_eq!(res_tlv.tlv_type(), &TlvType::End);
}

#[test]
fn parse_frame_with_two_tlv() {
    let frame = &[2, 4, b'a', b'b', b'c', b'd', 0, 0];
    let mut result = parse_frame(frame);
    assert_eq!(result.len(), 2);
    //end tlv here
    let tlv = result.pop().unwrap().expect("end tlv should be here");
    assert_eq!(tlv.tlv_type(), &TlvType::End);

    let tlv = result
        .pop()
        .unwrap()
        .expect("chassis id tlv should be here");
    assert_eq!(tlv.tlv_type(), &TlvType::ChassisID);
    let expected_value = "abcd".as_bytes();
    assert_eq!(tlv.len(), expected_value.len());
    assert_eq!(tlv.value().as_slice(), expected_value);
}

#[test]
fn parse_frame_3tlvs_last_one_error() {
    let frame = "\x02\x03123\x04\x0512345\x03\x1ftoo short".as_bytes();
    let mut tlvs = parse_frame(&frame);
    assert_eq!(tlvs.pop().unwrap().unwrap_err(), ParsingError::TooShort);
    let second_tlv = tlvs.pop().unwrap().unwrap();
    assert_eq!(
        String::from_utf8(second_tlv.value().clone()).unwrap(),
        "12345"
    );
    assert_eq!(second_tlv.len(), 5);
}

#[test]
fn parse_frame_stops_parsing_after_error() {
    let frame = "\x02\x03123\x04\x0512345\x03\x1ftoo short\x00\x00".as_bytes();
    let tlvs = parse_frame(&frame);
    assert_eq!(tlvs.len(), 3);
}
