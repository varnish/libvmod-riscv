use std::process::Command;

fn help(binary: &str) -> String {
    let output = Command::new(binary)
        .arg("--help")
        .output()
        .expect("dumper binary starts");
    assert!(
        output.status.success(),
        "dumper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("help is UTF-8")
}

#[test]
fn both_dumpers_share_the_exercised_cli_contract() {
    let ir = help(env!("CARGO_BIN_EXE_dump_ir"));
    let riscv = help(env!("CARGO_BIN_EXE_dump_riscv"));
    assert!(ir.contains("[-O0] <policy.vcl|->"), "{ir}");
    assert!(riscv.contains("[-O0] <policy.vcl|->"), "{riscv}");
}
