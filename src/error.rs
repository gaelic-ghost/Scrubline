use std::error::Error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum AppError {
    SameInputAndOutput,
    OpenInput(io::Error),
    CreateOutput(io::Error),
    ReadInput {
        line: usize,
        source: io::Error,
    },
    WriteOutput(io::Error),
    FlushOutput(io::Error),
    InvalidJson {
        line: usize,
        column: usize,
        reason: &'static str,
    },
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameInputAndOutput => write!(
                formatter,
                "the input and output refer to the same path; choose a different output so the source log is not overwritten"
            ),
            Self::OpenInput(_) => write!(
                formatter,
                "unable to open the input file; verify that it exists and that the current user can read it"
            ),
            Self::CreateOutput(_) => write!(
                formatter,
                "unable to create the output file; verify that its parent directory exists and is writable"
            ),
            Self::ReadInput { line, .. } => write!(
                formatter,
                "unable to read input near line {line}; the source may not be valid UTF-8 or an I/O error may have interrupted the stream"
            ),
            Self::WriteOutput(_) => write!(
                formatter,
                "unable to write scrubbed output; the destination may be closed, full, or no longer writable"
            ),
            Self::FlushOutput(_) => write!(
                formatter,
                "unable to finish writing scrubbed output; the destination may be full or no longer writable"
            ),
            Self::InvalidJson {
                line,
                column,
                reason,
            } => write!(
                formatter,
                "invalid JSONL at line {line}, column {column}: {reason}; no source value is included in this diagnostic"
            ),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpenInput(source)
            | Self::CreateOutput(source)
            | Self::WriteOutput(source)
            | Self::FlushOutput(source)
            | Self::ReadInput { source, .. } => Some(source),
            Self::SameInputAndOutput | Self::InvalidJson { .. } => None,
        }
    }
}
