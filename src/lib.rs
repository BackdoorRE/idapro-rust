//! Provides a low-level interface to IDA Pro via IDC and IDAPython
//! scripts represented as strings.

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate serde_derive;

use std::fs;
use std::fs::File;
use std::io::Write;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use failure::Error;

#[derive(Debug, Fail)]
pub enum IdaError {
    #[fail(display = "invalid path to IDA executable: {}", path)]
    InvalidPath { path: String },
    #[fail(display = "invalid analysis target: {:?}", path)]
    InvalidTarget { path: PathBuf },
    #[fail(display = "invalid analysis target {:?}; would clobber {:?}", path, clobber)]
    InvalidTargetClobber { path: PathBuf, clobber: PathBuf },
}

// Exported basic block information
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct Block {
    pub start_addr: u64,
    pub end_addr: u64,
    pub t_reg: Option<bool>,
    pub dests: Vec<u64>,
}

// Exported function information
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct Function {
    pub name: String,
    pub start_addr: u64,
    pub end_addr: u64,
    pub blocks: Vec<Block>,
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
    wine: bool,
    docker_image: Option<String>,
    docker_tag: Option<String>,
    docker_local_dir: Option<PathBuf>,
    docker_mount_dir: Option<String>,
    docker_clobber: bool,
    remove_database: bool,
    script_type: Type,
}

lazy_static! {
    static ref CAPABILITIES: Regex =
        Regex::new("^(?:.*[/\\\\])?ida(?P<mode>l|q|w|t)(?P<bits>(?:64)?)(?P<exe>(?:\\.exe)?)$")
            .unwrap();
    static ref WINDOWS_PATH: Regex = Regex::new("^[A-Z]:").unwrap();
}

fn windowsify<S: AsRef<str>>(path: S) -> String {
    let path = path.as_ref();
    if WINDOWS_PATH.is_match(path.as_ref()) {
        path.to_owned()
    } else {
        // NOTE: all paths are canonicalised, so we expect it to begin with /
        let mut rpath = String::from(r"Z:\");
        rpath.push_str(
            if path.starts_with("/") {
                &path[1..]
            } else {
                path
            }
            .replace("/", "\\")
            .as_ref(),
        );
        rpath
    }
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
    pub fn new(ida_path: &str) -> Result<IDA, Error> {
        CAPABILITIES
            .captures(ida_path)
            .map(|caps| IDA {
                exec: ida_path.to_owned(),
                bits: if &caps["bits"] == "" {
                    Bits::Bits32
                } else {
                    Bits::Bits64
                },
                mode: if &caps["mode"] == "l" || &caps["mode"] == "t" {
                    Mode::Headless
                } else {
                    Mode::Graphical
                },
                docker_image: None,
                docker_tag: None,
                docker_local_dir: None,
                docker_mount_dir: None,
                docker_clobber: false,
                wine: !caps["exe"].is_empty(),
                remove_database: true,
                script_type: Type::Python,
            })
            .ok_or(
                IdaError::InvalidPath {
                    path: ida_path.to_owned(),
                }
                .into(),
            )
    }

    pub fn dockerised<R: AsRef<Path>>(
        image: &str,
        tag: &str,
        local: R,
        mount: &str,
        ida_path: &str,
    ) -> Result<IDA, Error> {
        Self::new(ida_path).and_then(|i| i.with_docker(image, tag, local, mount))
    }

    /// Sets if the IDA database is removed upon script completion.
    pub fn remove_database(mut self, remove: bool) -> IDA {
        self.remove_database = remove;
        self
    }

    pub fn with_docker<R: AsRef<Path>>(
        mut self,
        image: &str,
        tag: &str,
        local: R,
        mount: &str,
    ) -> Result<IDA, Error> {
        self.docker_image = Some(image.to_owned());
        self.docker_tag = Some(tag.to_owned());
        self.docker_local_dir = Some(local.as_ref().canonicalize()?);
        self.docker_mount_dir = Some(mount.to_owned());
        Ok(self)
    }

    pub fn docker_clobbers(mut self, will_clobber: bool) -> IDA {
        self.docker_clobber = will_clobber;
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

    /// Returns `true` if the IDA instance will be launched from a docker
    /// container.
    pub fn is_dockerised(&self) -> bool {
        self.docker_image.is_some()
    }

    /// Returns `true` if IDA instance will be launched from wine or
    /// wineconsole.
    pub fn is_wine(&self) -> bool {
        self.wine
    }

    /// Runs the script with the contents given as `script` on the `target`
    /// executable.
    pub fn run<T: AsRef<Path>>(&self, script: &str, target: T) -> Result<bool, Error> {
        let target = target.as_ref().canonicalize()?;
        let mut copied_target = false;
        let mut orig_path = None;

        let mut temp_builder = tempfile::Builder::new();
        temp_builder.prefix("ida");
        temp_builder.suffix(if self.script_type == Type::Python {
            ".py"
        } else {
            ".idc"
        });
        let mut script_file = if let Some(ref dir) = self.docker_local_dir {
            temp_builder.tempfile_in(dir)?
        } else {
            temp_builder.tempfile()?
        };

        script_file.write(script.as_bytes())?;
        script_file.as_file().sync_all()?;

        let (mut cmd, rscript, rtarget) = if self.is_dockerised() {
            let mut cmd = process::Command::new("docker");
            let local_dir = self.docker_local_dir.as_ref().unwrap();
            let mount_dir = self.docker_mount_dir.as_ref().unwrap();
            cmd.args(&[
                "run",
                "--rm",
                "-t",
                "-v",
                &format!("{}:{}", local_dir.display(), mount_dir,),
                &format!(
                    "{}:{}",
                    self.docker_image.as_ref().unwrap(),
                    self.docker_tag.as_ref().unwrap(),
                ),
            ]);
            if !self.is_wine() && self.is_headless() {
                cmd.args(&["-e", "TVHEADLESS=1"]);
            };
            let rscript: String =
                PathBuf::from_iter(&[mount_dir.as_ref(), script_file.path().file_name().unwrap()])
                    .to_string_lossy()
                    .into_owned();

            let rtarget = if let Ok(suffix) = target.strip_prefix(local_dir) {
                let rtarget = PathBuf::from_iter(&[mount_dir.as_ref(), suffix]);
                if self.remove_database {
                    orig_path = Some(target)
                };
                rtarget
            } else {
                let file = target.file_name().ok_or_else(|| IdaError::InvalidTarget {
                    path: target.to_owned(),
                })?;
                let to = PathBuf::from_iter(&[local_dir.as_ref(), file]);
                // disallow clobbering
                if !self.docker_clobber && to.exists() {
                    return Err(IdaError::InvalidTargetClobber {
                        path: target.to_owned(),
                        clobber: to,
                    }.into())
                }
                let rtarget = PathBuf::from_iter(&[mount_dir.as_ref(), file]);
                fs::copy(target, &to)?;
                copied_target = true;
                orig_path = Some(to);
                rtarget
            };
            (cmd, rscript, rtarget)
        } else {
            let mut cmd = process::Command::new("/bin/sh");
            cmd.arg("-c");
            if !self.is_wine() && self.is_headless() {
                cmd.env("TVHEADLESS", "1");
            };
            if self.remove_database {
                orig_path = Some(target.to_owned())
            };
            (
                cmd,
                script_file.path().to_string_lossy().into_owned(),
                target,
            )
        };

        if self.wine {
            if self.is_headless() {
                cmd.args(&["wineconsole", "--backend=curses"]);
            } else {
                cmd.arg("wine");
            };

            let target_str = rtarget.to_string_lossy();
            cmd.args(&[
                &self.exec,
                "-A",
                &format!("-S{}", windowsify(rscript)),
                &windowsify(target_str),
            ]);
        } else {
            cmd.arg(&self.exec);
            let target_str = rtarget.to_string_lossy();
            cmd.args(&["-A", &format!("-S{}", rscript), target_str.as_ref()]);
        }

        let output = cmd.output()?;

        if copied_target {
            fs::remove_file(orig_path.as_ref().unwrap()).ok();
        };

        if self.remove_database {
            // Can fail, in the case of, e.g., an unpacked database.
            let target_path = format!(
                "{}.{}",
                orig_path.as_ref().unwrap().display(),
                if self.bits == Bits::Bits32 {
                    "idb"
                } else {
                    "i64"
                }
            );
            fs::remove_file(&target_path).ok();
        }

        Ok(output.status.success())
    }

    pub fn function_names<T: AsRef<Path>>(&self, target: T) -> Result<Vec<String>, Error> {
        let json = tempfile::Builder::new().suffix("json").tempfile()?;
        let path = json.into_temp_path();
        let command = format!(include_str!("../python/function_names.py"), path.display());

        self.run(&command, target)?;

        let json = File::open(&path)?;
        serde_json::from_reader::<_, Vec<String>>(&json).map_err(Error::from)
    }

    pub fn function_boundaries<T: AsRef<Path>>(&self, target: T) -> Result<Vec<(u64, u64)>, Error> {
        let json = tempfile::Builder::new().suffix("json").tempfile()?;
        let path = json.into_temp_path();
        let command = format!(include_str!("../python/function_starts.py"), path.display());

        self.run(&command, target)?;

        let json = File::open(&path)?;
        serde_json::from_reader::<_, Vec<(u64, u64)>>(&json).map_err(Error::from)
    }

    pub fn function_cfgs<T: AsRef<Path>>(&self, target: T) -> Result<Vec<Function>, Error> {
        let json = tempfile::Builder::new().suffix("json").tempfile()?;
        let path = json.into_temp_path();
        let command = format!(include_str!("../python/function_cfgs.py"), path.display());

        self.run(&command, target)?;

        let json = File::open(&path)?;
        serde_json::from_reader::<_, Vec<Function>>(&json).map_err(Error::from)
    }
}
