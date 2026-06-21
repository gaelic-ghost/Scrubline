use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

const HELP: &str = "\
Remove secrets and personal information from logs as they stream.

Usage: scrubline [OPTIONS] [INPUT]

Arguments:
  [INPUT]  Input file to scrub; use - or omit it to read standard input

Options:
      --format <FORMAT>  Input format: text or jsonl [default: text]
  -o, --output <OUTPUT>  Write scrubbed content to a file instead of standard output
      --no-report        Suppress aggregate redaction counts on standard error
  -h, --help             Print help
  -V, --version          Print version
";

#[derive(Debug, Eq, PartialEq)]
pub struct Cli {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub format: InputFormat,
    pub no_report: bool,
}

impl Cli {
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<ParseOutcome, CliError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        let mut input = None;
        let mut output = None;
        let mut format = InputFormat::Text;
        let mut no_report = false;
        let mut positional_only = false;

        while let Some(argument) = arguments.next() {
            if positional_only {
                set_input(&mut input, argument)?;
                continue;
            }

            if argument == OsStr::new("--") {
                positional_only = true;
            } else if argument == OsStr::new("-h") || argument == OsStr::new("--help") {
                return Ok(ParseOutcome::Help(HELP));
            } else if argument == OsStr::new("-V") || argument == OsStr::new("--version") {
                return Ok(ParseOutcome::Version(concat!(
                    "scrubline ",
                    env!("CARGO_PKG_VERSION")
                )));
            } else if argument == OsStr::new("--no-report") {
                no_report = true;
            } else if argument == OsStr::new("-o") || argument == OsStr::new("--output") {
                let value = arguments.next().ok_or(CliError::MissingOutputPath)?;
                if output.replace(PathBuf::from(value)).is_some() {
                    return Err(CliError::DuplicateOption("--output"));
                }
            } else if argument == OsStr::new("--format") {
                let value = arguments.next().ok_or(CliError::MissingFormat)?;
                format = InputFormat::parse(&value)?;
            } else if let Some(value) = argument
                .to_str()
                .and_then(|value| value.strip_prefix("--format="))
            {
                format = InputFormat::parse(OsStr::new(value))?;
            } else if argument.to_string_lossy().starts_with('-') && argument != OsStr::new("-") {
                return Err(CliError::UnknownOption);
            } else {
                set_input(&mut input, argument)?;
            }
        }

        Ok(ParseOutcome::Run(Self {
            input: input.unwrap_or_else(|| PathBuf::from("-")),
            output,
            format,
            no_report,
        }))
    }
}

fn set_input(input: &mut Option<PathBuf>, value: OsString) -> Result<(), CliError> {
    if input.replace(PathBuf::from(value)).is_some() {
        Err(CliError::MultipleInputs)
    } else {
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ParseOutcome {
    Run(Cli),
    Help(&'static str),
    Version(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputFormat {
    Text,
    Jsonl,
}

impl InputFormat {
    fn parse(value: &OsStr) -> Result<Self, CliError> {
        match value.to_str() {
            Some("text") => Ok(Self::Text),
            Some("jsonl") => Ok(Self::Jsonl),
            _ => Err(CliError::UnsupportedFormat(value.to_os_string())),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum CliError {
    MissingOutputPath,
    MissingFormat,
    DuplicateOption(&'static str),
    UnsupportedFormat(OsString),
    UnknownOption,
    MultipleInputs,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOutputPath => write!(
                formatter,
                "--output requires a destination path; provide one after the option"
            ),
            Self::MissingFormat => write!(
                formatter,
                "--format requires either 'text' or 'jsonl' after the option"
            ),
            Self::DuplicateOption(option) => {
                write!(
                    formatter,
                    "{option} was provided more than once; provide it once"
                )
            }
            Self::UnsupportedFormat(value) => write!(
                formatter,
                "unsupported input format '{}'; choose 'text' or 'jsonl'",
                value.to_string_lossy()
            ),
            Self::UnknownOption => write!(
                formatter,
                "an unknown option was provided; use --help to list supported options"
            ),
            Self::MultipleInputs => write!(
                formatter,
                "more than one input path was provided; Scrubline accepts one stream at a time"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{Cli, CliError, InputFormat, ParseOutcome};

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_jsonl_file_output() {
        let outcome = Cli::parse(args(&[
            "scrubline",
            "--format",
            "jsonl",
            "--output",
            "safe.jsonl",
            "input.jsonl",
        ]))
        .unwrap();

        assert_eq!(
            outcome,
            ParseOutcome::Run(Cli {
                input: PathBuf::from("input.jsonl"),
                output: Some(PathBuf::from("safe.jsonl")),
                format: InputFormat::Jsonl,
                no_report: false,
            })
        );
    }

    #[test]
    fn defaults_to_text_from_standard_input() {
        let outcome = Cli::parse(args(&["scrubline"])).unwrap();

        assert_eq!(
            outcome,
            ParseOutcome::Run(Cli {
                input: PathBuf::from("-"),
                output: None,
                format: InputFormat::Text,
                no_report: false,
            })
        );
    }

    #[test]
    fn rejects_multiple_inputs() {
        let error = Cli::parse(args(&["scrubline", "one.log", "two.log"])).unwrap_err();

        assert_eq!(error, CliError::MultipleInputs);
    }
}
