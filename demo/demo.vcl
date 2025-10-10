vcl 4.1;
import digest;
import riscv;
import std;

backend default {
	.host = "127.0.0.1";
	.port = "8081";
}

sub vcl_recv {
	riscv.fork("rusty.com");
	if (req.url != "/cat" && req.url != "/verify") {
		/* Verify request signature, decoded from base64 */
		if (!riscv.call("verify_signature", req.http.X-Signature)) {
			return (synth(403, "Forbidden: Invalid Signature"));
		}
	}

	/* Select a tenant to handle this request */
	riscv.fork(req.http.Host);
	/* Add CDNs custom header fields */
	set req.http.X-Tenant = riscv.current_name();
	/* We can call VCL-like functions */
	riscv.run();
	/* We can query what the machine wants to happen */
	if (riscv.want_result() == "synth") {
		/* And then do it for them */
		return (synth(riscv.want_status()));
	} else if (riscv.want_result() == "backend") {
		set req.http.X-Backend-Func = riscv.result_value(1);
		set req.http.X-Backend-Arg  = riscv.result_value(2);
		if (riscv.result_value(0) == 0) {
			return (pass);
		} else {
			return (hash);
		}
	}
}

sub vcl_deliver {
	if (req.http.X-Tenant) {
		riscv.run();
	}
}

sub vcl_backend_fetch {
	if (bereq.http.X-Tenant) {
		if (riscv.fork(bereq.http.X-Tenant)) {
			riscv.run();
			if (bereq.http.X-Backend-Func) {
				set bereq.backend = riscv.vm_backend(
						bereq.http.X-Backend-Func,
						bereq.http.X-Backend-Arg);
			}
		}
	}
}
sub vcl_backend_response {
	if (bereq.http.X-Tenant) {
		riscv.run();
	}
	set beresp.http.varnish-director = bereq.backend;
	set beresp.http.varnish-backend = beresp.backend;
}

sub vcl_init {
	/* Initialize some tenants from JSON */
	riscv.embed_tenants("""{
		"test.com": {
			"filename": "/home/gonzo/github/libvmod-riscv/program/cpp/basic.cpp",
			"arguments": ["Hello from RISC-V!"]
		},
		"rusty.com": {
			"filename": "rust:/home/gonzo/github/libvmod-riscv/program/rust",
			"arguments": ["Hello from Rust on RISC-V!"]
		}
	}""");
}
