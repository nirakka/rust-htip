#[derive(Debug, PartialEq, Eq)]
pub enum HtipError<'a> {
    TooShort,
    NotEqual(&'a [u8]),
    NotANumber(&'a [u8]),
    InvalidPercentage(&'a [u8]),
    InvalidMac(&'a [u8]),
}
