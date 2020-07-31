use lazy_static::lazy_static;

use crate::{InfoEntry, LintEntry, ParseData, ParsingError, TlvKey};
use std::collections::HashMap;
use std::fmt;

lazy_static! {
    static ref LINTS: HashMap<Lint, &'static str> = {
        let mut map = HashMap::new();
        map.insert(Lint::Error(1), "No End TLV");
        map
    };
}

static NODESC: &str = "No Description";

/// Type of a lint
#[derive(PartialEq, Eq, Hash)]
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
