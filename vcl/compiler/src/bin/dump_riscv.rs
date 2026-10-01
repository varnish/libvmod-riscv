use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use vcl_compiler::compile;

mod common;

const OBJDUMP: &str = "riscv64-linux-gnu-objdump";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dump_riscv: {error}");
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
    let compiled = compile(&source, options).map_err(|error| error.render(&path))?;
    let temporary = TempElf::write(&compiled.elf)?;
    let status = Command::new(OBJDUMP)
        .args([
            "--file-headers",
            "--section-headers",
            "--syms",
            "--disassemble",
            "--wide",
        ])
        .arg(&temporary.path)
        .status()
        .map_err(|error| format!("cannot run {OBJDUMP}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{OBJDUMP} exited with {status}"))
    }
}

struct TempElf {
    path: PathBuf,
}

impl TempElf {
    fn write(bytes: &[u8]) -> Result<Self, String> {
        for suffix in 0..100u8 {
            let path = std::env::temp_dir().join(format!(
                "vcl-compiler-dump-{}-{suffix}.elf",
                std::process::id()
            ));
            // The compiled policy can carry literals — an HMAC key, a token —
            // so the file is the author's alone, never the umask's idea of it.
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(bytes) {
                        let _ = fs::remove_file(&path);
                        return Err(format!(
                            "cannot write temporary ELF {}: {error}",
                            path.display()
                        ));
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "cannot create temporary ELF {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("cannot reserve a temporary ELF filename".to_string())
    }
}

impl Drop for TempElf {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn usage() -> String {
    "usage: cargo run -p vcl-compiler --bin dump_riscv -- [-O0] <policy.vcl|->".to_string()
}
