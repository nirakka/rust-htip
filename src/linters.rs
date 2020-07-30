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

#[derive(PartialEq, Eq, Hash)]
pub enum Lint {
    Warning(u8),
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

pub trait Linter {
    fn lint(&self, info: &[InfoEntry<'_>]) -> Vec<Lint>;
}

pub struct CheckEndTlv;

impl Linter for CheckEndTlv {
    fn lint(&self, info: &[InfoEntry<'_>]) -> Vec<Lint> {
        let mut res = vec![];
        match info.last() {
            //no end tlv
            None => res.push(Lint::Error(1)),
            Some(entry) => {
                if entry.0.tlv_type != 0 {
                    //last tlv is not end tlv
                    res.push(Lint::Error(1));
                }
            }
        }
        res
    }
}
