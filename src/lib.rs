//! You are probably looking for the [dispatcher::Dispatcher::parse()] method.
//!
//! To parse HTIP related data, first setup a new [Dispatcher] instance
//! and then pass the data to be parsed to the dispatcher's
//! [parse()](dispatcher::Dispatcher::parse()) method.
//!
//! After a successfull parse, you are looking into handling either your [FrameInfo] data,
//! or your [InvalidFrame] error.
//!
//! [FrameInfo] is split into three types of information:
//! * parsed tlv information as [InfoEntries](InfoEntry) (also see [parsers::ParseData])
//! * linting warinings & errors ([LintEntry])
//! * hard parsing errors ([ParsingError])

#![deny(broken_intra_doc_links)]
//TODO figure out proper visibilities
/// Organize parsers & linters into a single unit
pub mod dispatcher;
/// A collection of linters that check the contents of parsed information
/// for irregularities
mod linters;
/// A collection of parsers that check the contents of tlvs for structural
/// integrity and extract pieces of parsed information
mod parsers;
mod subkeys;
/// Type-Length-Value types
pub mod tlv;

pub use dispatcher::ParserKey as TlvKey;
pub use dispatcher::{Dispatcher, InvalidFrame};
pub use linters::Lint;
pub use parsers::ParseData;
pub use tlv::{TlvType, TLV};

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
///These are the errors that a basic parser may produce.
///The slice represents the original data that caused
///the error.
pub enum ParsingError<'a> {
    ///Not enough data to parse
    TooShort,
    ///The actual length is different from what is expected
    UnexpectedLength(usize),
    ///A sequence of bytes is different from what it was expected
    NotEqual(&'a [u8]),
    ///An invalid percentage, outside the range of [0-100]
    InvalidPercentage(u8),
    ///The text is not valid utf8
    InvalidText(std::str::Utf8Error),
    ///Unknown type/subtype
    Unknown,
}

/// A lint entry associated with a frame
#[derive(Debug)]
pub struct LintEntry {
    /// [Lint] type
    pub lint: Lint,
    /// Related tlv & prefix
    pub tlv_key: Option<TlvKey>,
    /// Any additional info, used to customize error message
    pub extra_info: Option<String>,
}

impl LintEntry {
    /// Create a new LintEntry of the given type
    pub fn new(lint: Lint) -> LintEntry {
        LintEntry {
            lint,
            tlv_key: None,
            extra_info: None,
        }
    }

    pub fn with_tlv(self, key: TlvKey) -> LintEntry {
        LintEntry {
            tlv_key: Some(key),
            ..self
        }
    }

    pub fn with_extra_info(self, info: String) -> LintEntry {
        LintEntry {
            extra_info: Some(info),
            ..self
        }
    }
}

impl fmt::Display for LintEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            vec![
                Some(self.lint.to_string()),
                self.tlv_key.clone().map(|tlvkey| tlvkey.to_string()),
                self.extra_info.clone()
            ]
            .into_iter()
            .filter(|info| info.is_some())
            .map(|info| info.unwrap())
            .collect::<Vec<_>>()
            .join(", ")
        )
    }
}

pub fn parse_captured<T: pcap::Activated>(mut capture: pcap::Capture<T>) {
    //static setup
    //1. setup our filter (broadcast + lldp)
    capture
        .filter("ether broadcast && ether proto 0x88cc")
        .expect("pcap: unable to set filter");
    //2. get a dispatcher instance
    let mut dispatcher = Dispatcher::new();

    loop {
        let cap_data = capture.next();
        match cap_data {
            Ok(data) => {
                //strip the ethernet header (14 bytes)
                if let Some(htip_frame) = data.get(14..) {
                    let parse_result = dispatcher.parse(htip_frame);
                    match parse_result {
                        Ok(data) => println!("{}\n", data),
                        Err(_err) => println!("skipping bad frame..\n"),
                    }
                }
            }
            //if calling next() causes an error (e.g. no more data), we bail
            Err(_) => break,
        }
    }
}
/// Represent the parsing data result for the tlv indicated by key
pub type InfoEntry = (TlvKey, ParseData);
/// Represent the parsing error for the tlv indicated by key
pub type ErrorEntry<'a> = (TlvKey, ParsingError<'a>);

/// A structure holding all the relevant information for a
/// parsed HTIP frame.
pub struct FrameInfo<'a> {
    /// A vector with all the TLVs
    pub tlvs: Vec<TLV<'a>>,
    /// Information extracted from each tlv, using the parsers
    pub info: Vec<InfoEntry>,
    /// Errors encountered by the parsers
    pub errors: Vec<ErrorEntry<'a>>,
    /// Additional check results performed by the linters
    pub lints: Vec<LintEntry>,
}

impl fmt::Display for FrameInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //concatenate all the tlvs into a string
        let tlv_string = self
            .tlvs
            .iter()
            .map(|tlv| tlv.to_string())
            .collect::<Vec<String>>()
            .join("\n");
        write!(
            f,
            "TLVs: {}\n\nInfo: {:?}\nErrors: {:?}\n\n",
            tlv_string, self.info, self.errors,
        )?;
        if !&self.lints.is_empty() {
            write!(f, "lints: ")?;
            for i in &self.lints {
                write!(f, "{}, ", i)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {}
