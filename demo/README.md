# Demo VCL

The demo VCL loads a C++ and Rust program, although it won't fail if either is missing. You will have to meet the pre-requisites of one or both languages in order for the VMOD to automatically build each.

The C++ builder has a dependency on the program path, but you can specify your path by setting the environment variable `RISCV_PROGRAM_PATH=$PWD` when starting `varnishd`. You could also modify the default program path [in the source code directly](/src/builder/builder.cpp). Both 32- and 64-bit is supposed for C++, where 32-bit is the lowest latency.

The Rust builder will simply try to run `cargo build --release` in the specified project folder. You can run this command yourself in the project to verify that it works. If it doesn't work then you can be sure it also doesn't work from the VMOD. Install a full 64-bit Linux RISC-V cross-compiler and make sure it's detected by the [compiler detection script](/program/detect_compiler.sh), and build the VMOD for 64-bit mode: `./build.sh --64`.

## vcl_init

In VCL init all tenants are defined using `riscv.embed_tenants()`.

## vcl_recv

This will create a new VM for that front- or backend- request:
```vcl
riscv.fork("rusty.com");
```
Once a VM has been created, it can be called into by simply calling `riscv.run();` in each VCL function. The appropriate function in the VM guest program will be called, if it exists. It it doesn't exist nothing happens.


# Test scripts

You can test the C++ program like so:
```sh
curl -D - http://127.0.0.1:8000 -H "Host: test.com"
```

You can test XML manipulation in C++ like so:
```sh
./test_xml.sh
```

You can test the Rust program like so:
```sh
curl -D - http://127.0.0.1:8000 -H "Host: rusty.com"
```

You can test Common Access Token in Rust like so:
```sh
./verify_token.sh
```
