use rust_htip::htip::*;

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

    let res: Result<(), HtipError> = parsers.iter_mut().try_for_each(|mut parser| {
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
