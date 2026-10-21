//! Fresh verifier-only replay of one public fixture directory.

use std::{error::Error, path::PathBuf};

/// Requires an explicit public fixture and prints only independently reproduced results.
fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("verify")) {
        return Err("expected verify <public-directory>".into());
    }
    let path = PathBuf::from(args.next().ok_or("missing public directory")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    print!("{}", houseki_ledger_qualification::verify(&path)?.report());
    Ok(())
}
