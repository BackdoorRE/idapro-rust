//! Provides a low-level interface to IDA Pro via IDC and IDAPython
//! scripts represented as strings.

#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate tempfile;
extern crate failure;
#[macro_use]
extern crate failure_derive;

use std::fs::remove_file;
use std::process;
use std::io::Write;

use regex::Regex;
use tempfile::NamedTempFileOptions;

use failure::Error as FError;

#[derive(Debug, Fail)]
enum Error {
    #[fail(display = "invalid path to IDA executable: {}", path)]
    InvalidPath {
        path: String,
    },
}

/// IDA analysis capability.
#[derive(Debug, PartialEq)]
pub enum Bits {
    Bits32,
    Bits64,
}

/// IDA execution mode.
#[derive(Debug, PartialEq)]
pub enum Mode {
    Headless,
    Graphical,
}

/// IDA script type.
#[derive(Debug, PartialEq)]
pub enum Type {
    IDC,
    Python,
}

/// An IDA context for interfacing with IDA Pro.
#[derive(Debug, PartialEq)]
pub struct IDA {
    exec: String,
    bits: Bits,
    mode: Mode,
    remove_database: bool,
    script_type: Type,
}

lazy_static! {
    static ref CAPABILITIES: Regex =
        Regex::new("^(?:.*/)?ida(?P<mode>l|q|w)(?P<bits>(?:64)?)$").unwrap();
}

/// IDA implements the core functionality of rida it provides a context with
/// known capabilities upon creation.
impl IDA {
    /// Creates a new context to interface with IDA; the default script type is
    /// IDA, and the generated IDA database shall be removed upon script
    /// termination.
    /// 
    /// The capabilities of the IDA context are inferred from the filename of
    /// the given IDA executable. For instance: `idal64` will run headless in
    /// 64-bit mode, whereas `idaq` will run with a graphical interface in
    /// 32-bit mode.
    pub fn new(ida_path: &str) -> Result<IDA, FError> {
        CAPABILITIES.captures(ida_path)
            .map(|caps| IDA {
                exec: ida_path.to_owned(),
                bits: if &caps["bits"] == "" { Bits::Bits32 } else { Bits::Bits64 },
                mode: if &caps["mode"] == "l" { Mode::Headless } else { Mode::Graphical },
                remove_database: true,
                script_type: Type::Python,
            })
            .ok_or(Error::InvalidPath { path: ida_path.to_owned() }.into())
    }

    /// Sets if the IDA database is removed upon script completion.
    pub fn remove_database(mut self, remove: bool) -> IDA {
        self.remove_database = remove;
        self
    }

    /// Sets the script type.
    pub fn script_type(mut self, script_type: Type) -> IDA {
        self.script_type = script_type;
        self
    }

    /// Returns `true` if the IDA instance will run without a GUI (i.e. it
    /// will be headless).
    pub fn is_headless(&self) -> bool {
        self.mode == Mode::Headless
    }

    /// Returns `true` if the IDA instance will support loading 64-bit
    /// binaries.
    pub fn is_64bit(&self) -> bool {
        self.bits == Bits::Bits64
    }

    /// Runs the script with the contents given as `script` on the `target`
    /// executable.
    pub fn run(&self, script: &str, target: &str) -> Result<bool, FError> {
        let mut script_file = NamedTempFileOptions::new()
            .suffix(if self.script_type == Type::Python { ".py" } else { ".idc" })
            .create()?;

        script_file.write(script.as_bytes())?;
        script_file.sync_all()?;

        let mut cmd = process::Command::new(&self.exec);

        if self.mode == Mode::Headless {
            cmd.env("TVHEADLESS", "1");
        }

        cmd.args(&["-A", &format!("-S{}", script_file.path().display()), target]);

        let output = cmd.output()?;

        if self.remove_database {
            // Can fail, in the case of, e.g., an unpacked database.
            let target_path = format!("{}.{}", target, if self.bits == Bits::Bits32 { "idb" } else { "i64" });
            remove_file(&target_path).ok();
        }

        Ok(output.status.success())
    }
}
