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
