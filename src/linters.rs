use lazy_static::lazy_static;

use crate::{InfoEntry, LintEntry, ParseData, ParsingError, TlvKey};
use std::collections::HashMap;
use std::fmt;

lazy_static! {
    static ref LINTS: HashMap<Lint, &'static str> = {
        vec![
            (Lint::Error(1), "No End TLV"),
            (Lint::Warning(1), "Invalid Characters"),
        ]
        .into_iter()
        .collect()
    };
}

static NODESC: &str = "No Description";

/// Type of a lint
#[derive(PartialEq, Eq, Hash, Debug)]
pub enum Lint {
    /// A warning; althoug irregular it can still be used
    Warning(u8),
    /// Represents a clear violation of a rule in the specification
    Error(u8),
}

impl fmt::Display for Lint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lint::Error(e) => write!(f, "E{}: {}", e, LINTS.get(self).unwrap_or(&NODESC)),
            Lint::Warning(w) => write!(f, "W{}: {}", w, LINTS.get(self).unwrap_or(&NODESC)),
        }
    }
}

/// Checks for abnormal content in parsed information
pub trait Linter {
    /// Check the supplied info entries for abnormal content
    /// # Arguments
    ///
    /// * `info` - A collection of pieces of information, parsed
    /// from tlvs, which preserve their original order
    fn lint(&self, info: &[InfoEntry<'_>]) -> Vec<LintEntry>;
}

/// Linter that checks if an End TLV is present
pub struct CheckEndTlv;

impl Linter for CheckEndTlv {
    fn lint(&self, info: &[InfoEntry<'_>]) -> Vec<LintEntry> {
        let mut res = vec![];
        match info.last() {
            //no end tlv
            None => res.push(LintEntry::new(Lint::Error(1))),
            Some(entry) => {
                if entry.0.tlv_type != 0 {
                    //last tlv is not end tlv
                    res.push(LintEntry::new(Lint::Error(1)))
                }
            }
        }
        res
    }
}

pub struct InvalidChars {
    allowed: HashMap<TlvKey, String>,
}

impl InvalidChars {
    pub fn new() -> Self {
        let allowed = vec![
            //entry for machine information ID = 1
            (
                TlvKey::htip(b"\x01\x01".to_vec()),
                ('a'..'z')
                    .chain('A'..'Z')
                    .chain('0'..'9')
                    .chain(",-'()+./:=?;!*#@$_%".chars())
                    .collect::<String>(),
            ),
            //TODO add the entries below!
            //you insert a tuplet (tlvkey, allowed_chars_as_string)
            //
            //TODO machine information id = 2
            //TODO machine information id = 4 (same as ID 1? refactor!)
            //TODO machine information id = 50
            //TODO Double check, make sure we're not missing anything!
        ]
        .into_iter()
        .collect();
        InvalidChars { allowed }
    }
}

impl Linter for InvalidChars {
    fn lint(&self, info: &[InfoEntry<'_>]) -> Vec<LintEntry> {
        vec!()
        //TODO complete this!
        //for all tlvs
        //...if we know the tlv
        //...check the contents
        //
        //... for each info_entry
        //return:  LintEntry::new(Lint::Warning(1))
        //                  .with_tlv(info_entry.0 (probably needs clone))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_end_tlv_lints_on_empty_input() {
        let entries = vec![];
        let linter = CheckEndTlv;
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].lint, Lint::Error(1));
    }

    #[test]
    fn check_end_tlv_lints_on_wrong_last_entry() {
        let entries = vec![(TlvKey::new(1, vec![]), Ok(ParseData::Null))];
        let linter = CheckEndTlv;
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].lint, Lint::Error(1));
    }

    #[test]
    fn check_end_tlv_doesnt_lint_on_correct_last_entry() {
        let entries = vec![(TlvKey::new(0, vec![]), Ok(ParseData::Null))];
        let linter = CheckEndTlv;
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn invalid_chars_in_device_category() {
        let entries = vec![
            (
                TlvKey::htip(b"\x01\x01".to_vec()),
                Ok(ParseData::Text("man_id\x00".to_string())),
            ),
            (TlvKey::new(0, b"".to_vec()), Ok(ParseData::Null)),
        ];
        let linter = InvalidChars::new();
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0]
                .tlv_key
                .as_ref()
                .expect("The linter must put a tlv key in its result!"),
            &TlvKey::htip(b"\x01\x01".to_vec())
        );
    }

    #[test]
    fn invalid_chars_in_maker_code() {
        let entries = vec![
            //this is correct, it should not trigger an error!
            (
                TlvKey::htip(b"\x01\x01".to_vec()),
                Ok(ParseData::Text("device_category".to_string())),
            ),
            //this triggers error, all letters are wrong!
            (
                TlvKey::htip(b"\x01\x02".to_vec()),
                Ok(ParseData::Text("WRONG\x00".to_string())),
            ),
            //this is ok
            (TlvKey::new(0, b"".to_vec()), Ok(ParseData::Null)),
        ];
        let linter = InvalidChars::new();
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0]
                .tlv_key
                .as_ref()
                .expect("The linter must put a tlv key in its result!"),
            &TlvKey::htip(b"\x01\x02".to_vec())
        );
    }

    #[test]
    fn invalid_chars_in_maker_code_and_status_information() {
        let entries = vec![
            //this is correct, it should not trigger an error!
            (
                TlvKey::htip(b"\x01\x01".to_vec()),
                Ok(ParseData::Text("device_category".to_string())),
            ),
            //this triggers error, all letters are wrong!
            (
                TlvKey::htip(b"\x01\x02".to_vec()),
                Ok(ParseData::Text("WRONG\x00".to_string())),
            ),
            //this is ok
            (TlvKey::new(0, b"".to_vec()), Ok(ParseData::Null)),
            (
                TlvKey::htip(b"\x01\x50".to_vec()),
                Ok(ParseData::Text(
                    "status with underscores _ and #sharps and null\x00".to_string(),
                )),
            ),
        ];
        let linter = InvalidChars::new();
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0]
                .tlv_key
                .as_ref()
                .expect("The linter must put a tlv key in its result!"),
            &TlvKey::htip(b"\x01\x02".to_vec())
        );
        assert_eq!(
            result[1]
                .tlv_key
                .as_ref()
                .expect("The linter must put a tlv key in its result!"),
            &TlvKey::htip(b"\x01\x50".to_vec())
        );
    }
}
