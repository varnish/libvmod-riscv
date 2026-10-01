use std::process::ExitCode;

use vcl_compiler::dump_ir;

mod common;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dump_ir: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let Some((path, options)) = common::arguments(usage)? else {
        println!("{}", usage());
        return Ok(());
    };
    let source = common::read_source(&path)?;
    let output = dump_ir(&source, options).map_err(|error| error.render(&path))?;
    print!("{output}");
    Ok(())
}

fn usage() -> String {
    "usage: cargo run -p vcl-compiler --bin dump_ir -- [-O0] <policy.vcl|->".to_string()
}
