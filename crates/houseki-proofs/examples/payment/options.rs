//! Small bounded command line surface for public demonstration parameters.

use std::{error::Error, path::PathBuf};

/// Public counts and an optional destination for public artifacts only.
pub(super) struct Options {
    /// Actual input count, defaulting to the priority maximum.
    pub(super) inputs: usize,

    /// Actual output count, defaulting to recipient plus change.
    pub(super) outputs: usize,

    /// Optional fresh artifact directory.
    pub(super) directory: Option<PathBuf>,

    /// Reuses one output opening at two separately funded original positions.
    pub(super) repeated: bool,
}

impl Options {
    /// Parses explicit count flags without accepting unsupported shapes or ignored arguments.
    pub(super) fn parse(args: impl Iterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut result = Self {
            inputs: 4,
            outputs: 2,
            directory: None,
            repeated: false,
        };
        let mut args = args;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--inputs" => result.inputs = args.next().ok_or("missing input count")?.parse()?,
                "--outputs" => {
                    result.outputs = args.next().ok_or("missing output count")?.parse()?
                }
                "--directory" => {
                    result.directory = Some(args.next().ok_or("missing output directory")?.into())
                }
                "--repeated" => result.repeated = true,
                _ => return Err("expected --inputs, --outputs, --directory or --repeated".into()),
            }
        }

        if !(1..=4).contains(&result.inputs)
            || !(1..=2).contains(&result.outputs)
            || (result.repeated && result.outputs != 2)
        {
            return Err("unsupported payment demonstration shape".into());
        }

        Ok(result)
    }
}

/// Public argument validation before any private owners are constructed.
#[cfg(test)]
mod tests {
    use super::*;

    /// Priority defaults and explicit one-output requests remain distinct valid cases.
    #[test]
    fn payment_options_enforce_supported_counts() {
        let defaults = Options::parse(std::iter::empty()).unwrap();
        assert_eq!((defaults.inputs, defaults.outputs), (4, 2));
        assert_eq!(
            Options::parse(["--outputs", "1"].map(String::from).into_iter())
                .unwrap()
                .outputs,
            1
        );
        for arguments in [
            vec!["--inputs", "5"],
            vec!["--outputs", "0"],
            vec!["--inputs"],
            vec!["--outputs", "1", "--repeated"],
            vec!["--unknown"],
        ] {
            assert!(Options::parse(arguments.into_iter().map(String::from)).is_err());
        }
    }
}
