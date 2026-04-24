//! Zerobase CLI.
//!
//! Subcommands operate on a directory given by `--db` (or `ZEROBASE_DB`). The
//! passphrase is read from `$ZEROBASE_PASSPHRASE` if set, otherwise prompted
//! interactively via `rpassword` (never echoed, never on argv).

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use secrecy::SecretString;
use zerobase::Db;

#[derive(Parser)]
#[command(name = "zerobase", version, about = "Zero-trust encrypted key-value store")]
struct Cli {
    /// Path to the database directory.
    #[arg(short, long, env = "ZEROBASE_DB", default_value = "./zerobase.db")]
    db: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new empty database protected by a passphrase.
    Init,
    /// Store a value under `key`. Value read from stdin if `--` used.
    Put {
        /// Key to store under.
        key: String,
        /// Value bytes. If omitted, read from stdin.
        value: Option<String>,
    },
    /// Fetch a value by key. Prints raw bytes to stdout; exits 1 if missing.
    Get {
        /// Key to fetch.
        key: String,
    },
    /// Delete a key.
    Del {
        /// Key to delete.
        key: String,
    },
    /// Force a MemTable → SSTable flush.
    Flush,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            // Never leak internal details to stdout. Stderr with a bland line.
            let _ = writeln!(io::stderr(), "error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let pass = read_passphrase(matches!(cli.cmd, Cmd::Init))?;

    match cli.cmd {
        Cmd::Init => {
            let db = Db::create(&cli.db, &pass)?;
            db.close()?;
            eprintln!("✓ created database at {}", cli.db.display());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Put { key, value } => {
            let mut db = Db::open(&cli.db, &pass)?;
            let value_bytes = match value {
                Some(v) => v.into_bytes(),
                None => {
                    let mut buf = Vec::new();
                    io::stdin().read_to_end(&mut buf)?;
                    buf
                }
            };
            db.put(key.into_bytes(), value_bytes)?;
            db.close()?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Get { key } => {
            let db = Db::open(&cli.db, &pass)?;
            match db.get(key.as_bytes()) {
                Some(v) => {
                    io::stdout().write_all(&v)?;
                    io::stdout().flush()?;
                    Ok(ExitCode::SUCCESS)
                }
                None => Ok(ExitCode::from(1)),
            }
        }
        Cmd::Del { key } => {
            let mut db = Db::open(&cli.db, &pass)?;
            db.delete(key.into_bytes())?;
            db.close()?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Flush => {
            let mut db = Db::open(&cli.db, &pass)?;
            db.flush()?;
            db.close()?;
            eprintln!("✓ flushed");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn read_passphrase(confirm: bool) -> io::Result<SecretString> {
    if let Ok(p) = std::env::var("ZEROBASE_PASSPHRASE") {
        return Ok(SecretString::new(p.into()));
    }
    let p1 = rpassword::prompt_password("passphrase: ")?;
    if confirm {
        let p2 = rpassword::prompt_password("confirm:    ")?;
        if p1 != p2 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "passphrases do not match"));
        }
    }
    Ok(SecretString::new(p1.into()))
}
