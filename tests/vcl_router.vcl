# The Varnish side of a VCL tenant, shared by the vcl_*.vtc tests: fork the
# tenant by Host, run its hook in every subroutine, and do what the hook
# returned. A hook that returns nothing, or a tenant without that hook, falls
# through to Varnish's built-in VCL, as a subroutine does in Varnish.
#
# The including VCL imports riscv, loads the tenants in vcl_init, and
# declares the backend.

sub vcl_recv {
	if (!riscv.fork(req.http.Host)) {
		return (synth(404, "No such tenant"));
	}
	riscv.run();
	if (riscv.want_result() == "synth") {
		return (synth(riscv.want_status(), riscv.want_reason()));
	} else if (riscv.want_result() == "pass") {
		return (pass);
	} else if (riscv.want_result() == "hash") {
		return (hash);
	}
}

sub vcl_hash {
	# The VMOD adds the tenant's name to the key before the hook runs.
	riscv.run();
	if (riscv.want_result() == "lookup") {
		return (lookup);
	}
}

sub vcl_hit {
	riscv.run();
	if (riscv.want_result() == "synth") {
		return (synth(riscv.want_status(), riscv.want_reason()));
	} else if (riscv.want_result() == "pass") {
		return (pass);
	} else if (riscv.want_result() == "miss") {
		return (miss);
	} else if (riscv.want_result() == "deliver") {
		return (deliver);
	}
}

sub vcl_miss {
	riscv.run();
	if (riscv.want_result() == "synth") {
		return (synth(riscv.want_status(), riscv.want_reason()));
	} else if (riscv.want_result() == "pass") {
		return (pass);
	} else if (riscv.want_result() == "fetch") {
		return (fetch);
	}
}

sub vcl_pass {
	riscv.run();
	if (riscv.want_result() == "synth") {
		return (synth(riscv.want_status(), riscv.want_reason()));
	} else if (riscv.want_result() == "fetch") {
		return (fetch);
	}
}

sub vcl_deliver {
	riscv.run();
	if (riscv.want_result() == "synth") {
		return (synth(riscv.want_status(), riscv.want_reason()));
	} else if (riscv.want_result() == "deliver") {
		return (deliver);
	}
}

sub vcl_synth {
	# A synth from before the fork (no tenant) has no hook to run.
	if (riscv.active()) {
		riscv.run();
		if (riscv.want_result() == "deliver") {
			return (deliver);
		}
	}
}

sub vcl_backend_fetch {
	# The client side cannot change Host, so this is the tenant that
	# handled the request.
	if (!riscv.fork(bereq.http.Host)) {
		return (error(503, "No such tenant"));
	}
	riscv.run();
	if (riscv.want_result() == "error") {
		return (error(riscv.want_status(), riscv.want_reason()));
	} else if (riscv.want_result() == "abandon") {
		return (abandon);
	} else if (riscv.want_result() == "fetch") {
		return (fetch);
	}
}

sub vcl_backend_response {
	riscv.run();
	if (riscv.want_result() == "error") {
		return (error(riscv.want_status(), riscv.want_reason()));
	} else if (riscv.want_result() == "abandon") {
		return (abandon);
	} else if (riscv.want_result() == "pass") {
		return (pass);
	} else if (riscv.want_result() == "deliver") {
		return (deliver);
	}
}

sub vcl_backend_error {
	if (riscv.active()) {
		riscv.run();
		if (riscv.want_result() == "abandon") {
			return (abandon);
		} else if (riscv.want_result() == "deliver") {
			return (deliver);
		}
	}
}
