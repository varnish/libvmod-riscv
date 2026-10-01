use std::env;
use std::fs;
use std::io::{self, Read as _};

use vcl_compiler::{CompileOptions, OptimizationLevel};

pub(crate) fn arguments(usage: fn() -> String) -> Result<Option<(String, CompileOptions)>, String> {
    let mut path = None;
    let mut options = CompileOptions::default();
    for argument in env::args().skip(1) {
        match argument.as_str() {
            "-O0" | "--no-opt" => options.optimization = OptimizationLevel::None,
            "-h" | "--help" => return Ok(None),
            _ if argument.starts_with('-') && argument != "-" => {
                return Err(format!("unknown option {argument:?}\n{}", usage()));
            }
            _ if path.is_none() => path = Some(argument),
            _ => return Err(format!("only one VCL input is accepted\n{}", usage())),
        }
    }
    path.map(|path| (path, options)).map(Some).ok_or_else(usage)
}

pub(crate) fn read_source(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut source = String::new();
        io::stdin()
            .read_to_string(&mut source)
            .map_err(|error| format!("cannot read stdin: {error}"))?;
        Ok(source)
    } else {
        fs::read_to_string(path).map_err(|error| format!("cannot read {path:?}: {error}"))
    }
}
