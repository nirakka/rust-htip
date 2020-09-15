use lazy_static::lazy_static;

use crate::{InfoEntry, LintEntry, ParseData, TlvKey};
use std::collections::HashMap;
use std::fmt;

lazy_static! {
    static ref LINTS: HashMap<Lint, &'static str> = {
        vec![
            (Lint::Error(1), "No End TLV"),
            (Lint::Warning(1), "Invalid Characters"),
            (Lint::Error(2), "Multiple Type 1 TLVs"),
            (Lint::Error(3), "Invalid MAC in Type 1 TLV"),
            (
                Lint::Error(4),
                "Type 1 TLV is neither MAC nor locally assigned",
            ),
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
    fn lint(&self, info: &[InfoEntry]) -> Vec<LintEntry>;
}

/// Linter that checks if an End TLV is present
pub struct CheckEndTlv;

impl Linter for CheckEndTlv {
    fn lint(&self, info: &[InfoEntry]) -> Vec<LintEntry> {
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

///Linter that checks for the presence of invalid characters in various TLVs
pub struct InvalidChars {
    allowed: HashMap<TlvKey, String>,
}

impl InvalidChars {
    pub fn new() -> Self {
        let allowed = vec![
            //entry for TLV type 4
            (
                TlvKey::new(4, vec![]),
                "\x20-'()+,./:=?;!*#@$_%"
                    .chars()
                    .chain('a'..='z')
                    .chain('A'..='Z')
                    .chain('0'..='9')
                    .collect::<String>(),
            ),
            //entry for HTIP machine information ID = 1
            (
                TlvKey::htip(b"\x01\x01".to_vec()),
                ('a'..='z')
                    .chain('A'..='Z')
                    .chain('0'..='9')
                    .chain(",-'()+./:=?;!*#@$_%".chars())
                    .collect::<String>(),
            ),
            //HTIP machine information id = 2
            (
                TlvKey::htip(b"\x01\x02".to_vec()),
                ('A'..='F').chain('0'..='9').collect::<String>(),
            ),
            //HTIP machine information id = 4 (same as ID 1?)
            (
                TlvKey::htip(b"\x01\x04".to_vec()),
                ('A'..='Z')
                    .chain('0'..='9')
                    .chain(",-'()+./:=?;!*#@$_%".chars())
                    .collect::<String>(),
            ),
            //HTIP machine information id = 50 (hex= 0x32)
            (
                TlvKey::htip(b"\x01\x32".to_vec()),
                ('A'..='Z')
                    .chain('0'..='9')
                    .chain(",.?!/*+-".chars())
                    .collect::<String>(),
            ),
        ]
        .into_iter()
        .collect();
        InvalidChars { allowed }
    }
}

impl Linter for InvalidChars {
    fn lint(&self, info: &[InfoEntry]) -> Vec<LintEntry> {
        info.iter()
            .filter_map(|(entry_key, entry_pdata)| {
                Some((self.allowed.get(entry_key)?, entry_key, entry_pdata))
            })
            .filter_map(|(allowed, key, data)| match data {
                ParseData::Text(data) => data
                    .chars()
                    .find(|c| !allowed.contains(*c))
                    .map(|_| LintEntry::new(Lint::Warning(1)).with_tlv(key.clone())),
                _ => None, //never happening
            })
            .collect()
    }
}

///This linter is for TLV type 1 and it checks the following:
/// 1. if more than one TLV type 1 is present issue error(2)
/// 2. if chassis ID subtype == 4 then length must be 6 or 8,
///     if not, issue error(3)
/// 3. for all other subtypes, issue error (4)
///
/// Lookup page 27 in jj-300.00.v3.pdf
///
/// Don't forget to set the lint entry key to TlvKey::new(1, vec![])
pub struct TLV1Linter;

impl Linter for TLV1Linter {
    fn lint(&self, info: &[InfoEntry]) -> Vec<LintEntry> {
        let dup = info.iter().filter(|(key, data)| key.tlv_type == 1).count();

        let le: Vec<_> = info
            .iter()
            .filter(|(key, data)| match data {
                ParseData::TypedData(4u8, d) => {
                    let size = d.len();
                    size > 4 && size != 6 && size != 8
                }
                _ => false,
            })
            .map(|_| LintEntry::new(Lint::Error(3)).with_tlv(TlvKey::new(1, vec![])))
            .collect();

        if dup > 1 {
            return vec![LintEntry::new(Lint::Error(2)).with_tlv(TlvKey::new(1, vec![]))];
        } else {
            le
        }
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
        let entries = vec![(TlvKey::new(1, vec![]), ParseData::Null)];
        let linter = CheckEndTlv;
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].lint, Lint::Error(1));
    }

    #[test]
    fn check_end_tlv_doesnt_lint_on_correct_last_entry() {
        let entries = vec![(TlvKey::new(0, vec![]), ParseData::Null)];
        let linter = CheckEndTlv;
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn invalid_chars_in_device_category() {
        let entries = vec![
            (
                TlvKey::htip(b"\x01\x01".to_vec()),
                ParseData::Text("man_id\x00".to_string()),
            ),
            (TlvKey::new(0, b"".to_vec()), ParseData::Null),
        ];
        let linter = InvalidChars::new();
        let result = linter.lint(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].lint, Lint::Warning(1));
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
                ParseData::Text("device_category".to_string()),
            ),
            //this triggers error, all letters are wrong!
            (
                TlvKey::htip(b"\x01\x02".to_vec()),
                ParseData::Text("WRONG\x00".to_string()),
            ),
            //this is ok
            (TlvKey::new(0, b"".to_vec()), ParseData::Null),
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
                ParseData::Text("device_category".to_string()),
            ),
            //this triggers error, all letters are wrong!
            (
                TlvKey::htip(b"\x01\x02".to_vec()),
                ParseData::Text("WRONG\x00".to_string()),
            ),
            //this is ok
            (TlvKey::new(0, b"".to_vec()), ParseData::Null),
            (
                TlvKey::htip(b"\x01\x32".to_vec()),
                ParseData::Text("status with underscores _ and #sharps and null\x00".to_string()),
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
            &TlvKey::htip(b"\x01\x32".to_vec())
        );
    }

    #[test]
    fn invalid_chars_out_of_order_entries_and_others_succeeds() {
        let entries = vec![
            //error!
            (
                TlvKey::htip(b"\x01\x32".to_vec()),
                ParseData::Text("status with underscores _ and #sharps and null\x00".to_string()),
            ),
            //this is ok
            (TlvKey::new(0, b"".to_vec()), ParseData::Null),
            //this triggers error, all letters are wrong!
            (
                TlvKey::htip(b"\x01\x02".to_vec()),
                ParseData::Text("WRONG\x00".to_string()),
            ),
            //this is correct, it should not trigger an error!
            (
                TlvKey::htip(b"\x01\x01".to_vec()),
                ParseData::Text("device_category".to_string()),
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
            &TlvKey::htip(b"\x01\x32".to_vec())
        );
        assert_eq!(
            result[1]
                .tlv_key
                .as_ref()
                .expect("The linter must put a tlv key in its result!"),
            &TlvKey::htip(b"\x01\x02".to_vec())
        );
    }

    #[test]
    fn tlv1linter_multiple_tlvs_error() {
        let entries = vec![
            //first tlv type 1
            (
                TlvKey::new(1, vec![]),
                ParseData::TypedData(4, b"abcdef".to_vec()),
            ),
            //second tlv type 1
            (
                TlvKey::new(1, vec![]),
                ParseData::TypedData(4, b"abcdef".to_vec()),
            ),
        ];
        let linter = TLV1Linter;
        let result = linter.lint(&entries);

        let many_tlvs_lint = result
            .into_iter()
            .find(|entry| entry.lint == Lint::Error(2));
        match many_tlvs_lint {
            None => panic!("Multiple TLV type 1 error not raised!"),
            Some(entry) => assert_eq!(entry.tlv_key.unwrap().tlv_type, 1),
        }
    }

    #[test]
    fn tlv1linter_invalid_mac() {
        let entries = vec![
            //first tlv type 1
            (
                TlvKey::new(1, vec![]),
                ParseData::TypedData(4, b"it doesn't matter, it's too long".to_vec()),
            ),
        ];
        let linter = TLV1Linter;
        let result = linter.lint(&entries);

        let many_tlvs_lint = result
            .into_iter()
            .find(|entry| entry.lint == Lint::Error(3));
        match many_tlvs_lint {
            None => panic!("Invalid MAC address error not raised!"),
            Some(entry) => assert_eq!(entry.tlv_key.unwrap().tlv_type, 1),
        }
    }

    #[test]
    fn tlv1linter_no_lint_on_correct_mac6_entry() {
        let entries = vec![(
            TlvKey::new(1, vec![]),
            //subtype is 4, 6 bytes, we should be fine
            ParseData::TypedData(4, b"ABCDEF".to_vec()),
        )];
        let linter = TLV1Linter;
        let result = linter.lint(&entries);
        assert!(result.is_empty(), "there should not be any errors here!");
    }

    #[test]
    fn tlv1linter_no_lint_on_correct_mac8_entry() {
        let entries = vec![(
            TlvKey::new(1, vec![]),
            //subtype is 4, 8 bytes(EUI64), we should be fine
            ParseData::TypedData(4, b"ABCDEF12".to_vec()),
        )];
        let linter = TLV1Linter;
        let result = linter.lint(&entries);
        assert!(result.is_empty(), "there should not be any errors here!");
    }
}
