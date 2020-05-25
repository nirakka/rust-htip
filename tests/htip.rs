#![allow(deprecated)]
use macaddr::MacAddr6;
use rust_htip::htip::*;
use std::convert::TryInto;

#[test]
fn dummy_forwards_buffer_and_returns_value() {
    let input = vec![0x00, 0x01, 0x02];
    let mut dummy = Dummy(2);
    let remainder = dummy.parse(&input).unwrap();

    assert_eq!(remainder.len(), 1);
    assert_eq!(remainder[0], 0x02);
    assert_eq!(dummy.data().into_u32(), Some(2));
}

#[test]
fn number_parses_1byte_value() {
    let input = vec![0x01, 0xff, 0x3c];
    let mut parser = SizedNumber::new(NumberSize::One);
    let remainder = parser.parse(&input).unwrap();

    assert_eq!(remainder.len(), 1);
    assert_eq!(parser.data().into_u32(), Some(255));
    assert_eq!(remainder[0], 0x3c);
}

#[test]
fn number_parses_2byte_value() {
    let input = vec![0x02, 0x02, 0x0a];
    let mut parser = SizedNumber::new(NumberSize::Two);
    let remainder = parser.parse(&input).unwrap();

    assert_eq!(remainder.len(), 0);
    assert_eq!(parser.data().into_u32(), Some(522));
}

#[test]
fn number_parses_4byte_value() {
    let input = vec![0x04, 0xff, 0xff, 0xff, 0xfe];
    let mut parser = SizedNumber::new(NumberSize::Four);
    let remainder = parser.parse(&input).unwrap();

    assert_eq!(remainder.len(), 0);
    assert_eq!(parser.data().into_u32(), Some(u32::max_value() - 1));
}

#[test]
fn number_fails_with_invalid_length() {
    let input = vec![0x0a, 0x02, 0x0a];
    let mut parser = SizedNumber::new(NumberSize::Two);
    let result = parser.parse(&input).err();

    assert_eq!(result, Some(HtipError::UnexpectedLength(10)));
}

#[test]
fn number_fails_for_short_input() {
    let input = vec![];
    let mut parser = SizedNumber::new(NumberSize::One);
    assert_eq!(parser.parse(&input).err(), Some(HtipError::TooShort));

    let input = vec![0x01];
    let mut parser = SizedNumber::new(NumberSize::One);
    assert_eq!(parser.parse(&input).err(), Some(HtipError::TooShort));
}

#[test]
fn number_parse_fails_for_short_buffer() {
    //we're expecting 4 bytes, only 3 are present...
    let input = vec![0x04, 0x00, 0x00, 0x00];
    let mut parser = SizedNumber::new(NumberSize::Four);
    assert_eq!(parser.parse(&input).err(), Some(HtipError::TooShort));
}

#[test]
fn multiple_parsers_succeed() {
    let mut parsers: Vec<Box<dyn Parser>> = vec![
        Box::new(SizedNumber::new(NumberSize::One)),
        Box::new(Dummy(2)),
        Box::new(SizedNumber::new(NumberSize::Four)),
    ];
    let input = vec![0x01, 0x0A, 0xFF, 0xFF, 0x04, 0xFF, 0xFF, 0xFE, 0x00];

    let mut slice = &input[..];

    let res: Result<(), HtipError> = parsers.iter_mut().try_for_each(|parser| {
        slice = parser.parse(slice).unwrap();
        Ok(())
    });

    //finala result was ok?
    assert!(res.is_ok());
    //is result exhausted?
    assert_eq!(slice.len(), 0);
    //test parser results?
    assert_eq!(parsers[0].data().into_u32(), Some(10));
    assert_eq!(parsers[1].data().into_u32(), Some(2));
    assert_eq!(parsers[2].data().into_u32(), Some(u32::max_value() - 511));
}

#[test]
fn fixed_sequence_matches_and_consumes_buffer() {
    let input = vec![b'1', b'2', b'3', b'4', b'5'];
    let mut parser = FixedSequence::new(input.clone());
    let result = parser.parse(&input);
    assert!(result.is_ok());

    //has the slice been advanced?
    let remainder = result.unwrap();
    assert!(remainder.is_empty());

    let data_vec: Vec<u8> = parser.data().try_into().unwrap();
    let data_string = String::from_utf8(data_vec).unwrap();
    assert_eq!(data_string, "12345");
}

#[test]
fn fixed_sequence_fails_short_buffer() {
    let input = vec![0x01, 0x02, 0x03];
    let mut clone = input.clone();
    let _ = clone.pop();
    let mut parser = FixedSequence::new(input);
    let result = parser.parse(&clone);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), HtipError::TooShort);
}

#[test]
fn fixed_sequence_does_not_match() {
    let original = vec![0x01, 0x02, 0x03, 0x04];
    let mut altered = original.clone();
    //change the copy a bit
    altered[2] = 0x04;
    altered.pop();
    let mut parser = FixedSequence::new(altered);
    let result = parser.parse(&original);
    assert!(result.is_err());

    let error = result.unwrap_err();
    //show where the first error occured
    assert_eq!(error, HtipError::NotEqual(&original[..3]));
}

#[test]
fn fixed_sequence_matches_with_longer_input() {
    let original = vec![0xff; 512];
    let altered = original[2..].to_owned();
    let mut parser = FixedSequence::new(altered);
    let result = parser.parse(&original);
    assert!(result.is_ok());

    //two bytes should still be remaining
    let remainder = result.unwrap();
    assert_eq!(remainder.len(), 2);
}

#[test]
fn percentage_is_valid_max_and_advances() {
    let input = vec![0x01, 0x64, 0xff, 0xff];
    let mut parser = Percentage::new();
    let result = parser.parse(&input);
    assert!(result.is_ok());

    let remainder = result.unwrap();
    assert_eq!(remainder.len(), 2);
    assert_eq!(remainder, &input[2..]);

    assert_eq!(parser.data().into_u32(), Some(100u32));
}

#[test]
fn percentage_is_valid_min() {
    let input = vec![0x01, 0x00];
    let mut parser = Percentage::new();
    let result = parser.parse(&input);
    assert!(result.is_ok());

    let remainder = result.unwrap();
    assert_eq!(remainder.len(), 0);

    assert_eq!(parser.data().into_u32(), Some(0u32));
}

#[test]
fn percentage_is_valid() {
    let input = vec![0x01, 0x32, 0x00];
    let mut parser = Percentage::new();
    let _ = parser.parse(&input);
    assert_eq!(parser.data().into_u32().unwrap(), 50u32);
}

#[test]
fn percentage_is_invalid() {
    let input = vec![0x01, 0x80];
    let mut parser = Percentage::new();
    let result = parser.parse(&input);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), HtipError::InvalidPercentage(128));
}

#[test]
fn percentage_invalid_length() {
    let input = vec![0xab, 0x80];
    let mut parser = Percentage::new();
    let result = parser.parse(&input);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), HtipError::UnexpectedLength(0xab));
}

#[test]
fn percentage_input_too_short() {
    let input = vec![0x01];
    let mut parser = Percentage::new();
    let result = parser.parse(&input);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), HtipError::TooShort);
}

#[test]
fn text_input_too_short_when_empty() {
    let input: Vec<u8> = vec![];
    assert_eq!(Text::new(2).parse(&input).unwrap_err(), HtipError::TooShort);
}

#[test]
fn text_is_1_byte_string_and_advances() {
    let input = vec![b'a', b'b'];
    let mut parser = Text::new(1);
    let result = parser.parse(&input);
    assert!(result.is_ok());

    let remainder = result.unwrap();
    assert_eq!(remainder.len(), 1);
    assert_eq!(remainder[0], b'b');

    let data = parser.data().into_string().unwrap();
    assert_eq!(data, String::from("a"));
}

#[test]
fn text_fails_invalid_utf8() {
    let invalid_input = b"\xff\x00\xff\xff\xff\xff\xff\xff";
    let mut parser = Text::new(8);
    let result = parser.parse(invalid_input);
    assert!(result.is_err());
    match result.unwrap_err() {
        HtipError::InvalidText(_) => (),
        _ => panic!("text parse result should be a std::str::Utf8Error"),
    }
}

#[test]
fn text_valid_string_less_than_max_size() {
    let input = b"this is a valid string";
    let mut parser = Text::new(255);
    let result = parser.parse(input);

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);

    assert_eq!(
        parser.data().into_string().unwrap(),
        String::from("this is a valid string")
    );
}

#[test]
fn text_includes_last_character() {
    let input = b"abcd";
    let mut parser = Text::new(4);
    let result = parser.parse(input);
    assert!(result.is_ok());

    assert_eq!(parser.data().into_string().unwrap(), String::from("abcd"));
}

#[test]
fn parse_one_mac_ok() {
    let input = b"\x01\x0A\x0B\x0C\x0E\x0F";
    let mut parser = Mac::new();
    let result = parser.parse(input);
    assert!(result.is_ok());
    //consumed everything?
    assert_eq!(result.unwrap().len(), 0);

    let macs = parser.data().into_mac().unwrap();
    //1 mac, equal to the one in the begining
    assert_eq!(macs.len(), 1);
    assert_eq!(macs[0], MacAddr6::new(0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F));
}

#[test]
fn short_mac() {
    let input = b"\x01\x0A\x0B\x0C\x0E";
    let mut parser = Mac::new();
    let result = parser.parse(input);
    assert_eq!(result.unwrap_err(), HtipError::TooShort);
}

#[test]
fn parse_three_macs_with_remainder() {
    let input = b"\x03ABCDEF123456\xFF\xFF\xFF\xFF\xFF\xFFremainder";
    let mut parser = Mac::new();
    let result = parser.parse(input).unwrap();
    assert_eq!(result, b"remainder");

    let macs = parser.data().into_mac().unwrap();

    assert_eq!(macs[0].as_ref(), b"ABCDEF");
    assert_eq!(macs[1].as_ref(), b"123456");
    assert!(macs[2].is_broadcast());
}
