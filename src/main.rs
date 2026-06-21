mod cli;
mod error;
mod json;
mod redact;
mod stream;

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

use crate::cli::{Cli, ParseOutcome};
use crate::error::AppError;
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
    if cli.input != Path::new("-")
        && cli
            .output
            .as_ref()
            .is_some_and(|output| output == &cli.input)
    {
        return Err(AppError::SameInputAndOutput);
    }

    let mut reader: Box<dyn io::BufRead> = if cli.input == Path::new("-") {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let file = File::open(&cli.input).map_err(AppError::OpenInput)?;
        Box::new(BufReader::new(file))
    };

    let mut writer: Box<dyn Write> = match cli.output {
        Some(path) => {
            let file = File::create(path).map_err(AppError::CreateOutput)?;
            Box::new(BufWriter::new(file))
        }
        None => Box::new(BufWriter::new(io::stdout())),
    };

    let redactor = Redactor::support_safe();
    let counts = stream::process(&mut reader, &mut writer, cli.format, &redactor)?;
    writer.flush().map_err(AppError::FlushOutput)?;

    if !cli.no_report {
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
