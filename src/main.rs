use chrono::Local;
use clap::Parser;
use env_logger::{
    Builder,
    WriteStyle,
};
use log::LevelFilter;
use std::{
    io::Write as _,
    path::PathBuf,
};

fn file_validator(path: &str) -> Result<PathBuf, &'static str> {
    let path: PathBuf = path.into();
    if !path.exists() {
        Err("input file does not exist")
    } else if !path.is_file() {
        Err("input file is not a file")
    } else {
        Ok(path)
    }
}

fn directory_validator(path: &str) -> Result<PathBuf, &'static str> {
    let path: PathBuf = path.into();
    if !path.exists() {
        Err("input directory does not exist")
    } else if !path.is_dir() {
        Err("input directory is not a directory")
    } else {
        Ok(path)
    }
}

#[derive(Parser)]
struct Cli {
    /// The input PE to scrape type information from
    #[arg(value_parser = file_validator)]
    input_image: PathBuf,

    /// The address bin to use when converting RVAs to IDs
    #[arg(value_parser = file_validator)]
    address_bin: PathBuf,

    /// The directory to write outputs to
    #[arg(value_parser = directory_validator)]
    output_directory: PathBuf,
}

fn main() -> anyhow::Result<()> {
    Builder::new()
        .filter_level(LevelFilter::max())
        .write_style(WriteStyle::Always)
        .format(|buf, record| {
            let timestamp = Local::now().format("%r");
            let level = record.level();
            let style = buf.default_level_style(level);
            let args = record.args();
            writeln!(buf, "[{timestamp} {style}{level}{style:#}] {args}")
        })
        .init();
    let cli = Cli::parse();
    rtti_dump::scrape_type_information(&cli.input_image, &cli.address_bin, &cli.output_directory)
}
