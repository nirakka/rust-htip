use rust_htip::htip::*;
use rust_htip::*;

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
    let mut parser = Number::new(NumberSize::One);
    let remainder = parser.parse(&input).unwrap();
    assert_eq!(remainder.len(), 1);
    assert_eq!(parser.data().into_u32(), Some(255));
    assert_eq!(remainder[0], 0x3c);
}

#[test]
fn number_parses_2byte_value() {
    let input = vec![0x02, 0x02, 0x0a];
    let mut parser = Number::new(NumberSize::Two);
    let remainder = parser.parse(&input).unwrap();
    assert_eq!(remainder.len(), 0);
    assert_eq!(parser.data().into_u32(), Some(522));
}

#[test]
fn number_parses_4byte_value() {
    let input = vec![0x04, 0xff, 0xff, 0xff, 0xfe];
    let mut parser = Number::new(NumberSize::Four);
    let remainder = parser.parse(&input).unwrap();
    assert_eq!(remainder.len(), 0);
    assert_eq!(parser.data().into_u32(), Some(u32::max_value() - 1));
}

#[test]
fn number_fails_with_invalid_length() {
    let input = vec![0x0a, 0x02, 0x0a];
    let mut parser = Number::new(NumberSize::Two);
    let result = parser.parse(&input).err();
    assert_eq!(result, Some(HtipError::UnexpectedLength(10)));
}

#[test]
fn number_fails_for_short_input() {
    let input = vec![];
    let mut parser = Number::new(NumberSize::One);
    assert_eq!(parser.parse(&input).err(), Some(HtipError::TooShort));

    let input = vec![0x00];
    let mut parser = Number::new(NumberSize::One);
    assert_eq!(parser.parse(&input).err(), Some(HtipError::TooShort));
}
