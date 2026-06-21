mod cli;
mod error;
mod json;
mod output;
mod redact;
mod stream;

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;

use crate::cli::{Cli, ParseOutcome};
use crate::error::AppError;
use crate::output::TransactionalOutput;
use crate::redact::Redactor;

fn main() -> ExitCode {
    let cli = match Cli::parse(std::env::args_os()) {
        Ok(ParseOutcome::Run(cli)) => cli,
        Ok(ParseOutcome::Help(help)) => {
            print!("{help}");
            return ExitCode::SUCCESS;
        }
        Ok(ParseOutcome::Version(version)) => {
            println!("{version}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("scrubline: {error}");
            eprintln!("Try 'scrubline --help' for usage.");
            return ExitCode::from(2);
        }
    };

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("scrubline: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    let Cli {
        input,
        output,
        format,
        no_report,
    } = cli;

    let (mut reader, input_metadata): (Box<dyn io::BufRead>, Option<std::fs::Metadata>) =
        if input == std::path::Path::new("-") {
            (Box::new(BufReader::new(io::stdin())), None)
        } else {
            let file = File::open(&input).map_err(AppError::OpenInput)?;
            let metadata = file.metadata().map_err(AppError::OpenInput)?;
            (Box::new(BufReader::new(file)), Some(metadata))
        };

    let redactor = Redactor::support_safe();
    let counts = if let Some(output) = output {
        let mut writer = TransactionalOutput::create(&output, &input, input_metadata.as_ref())?;
        let counts = stream::process(&mut reader, &mut writer, format, &redactor)?;
        writer.commit()?;
        counts
    } else {
        let mut writer = BufWriter::new(io::stdout());
        let counts = stream::process(&mut reader, &mut writer, format, &redactor)?;
        writer.flush().map_err(AppError::FlushOutput)?;
        counts
    };

    if !no_report {
        eprintln!(
            "scrubline: redacted {} value(s) \
             (bearer_tokens={}, api_keys={}, email_addresses={}, ip_addresses={}, home_paths={}) \
             using policy support-safe",
            counts.total(),
            counts.bearer_tokens,
            counts.api_keys,
            counts.email_addresses,
            counts.ip_addresses,
            counts.home_paths
        );
    }

    Ok(())
}
