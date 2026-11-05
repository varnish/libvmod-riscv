vcl 4.1;
import riscv;

/* Per-viewer HLS and DASH manifests from one cached copy.
   The origin is demo/streams: python3 -m http.server 8081 */
backend default {
	.host = "127.0.0.1";
	.port = "8081";
}

sub vcl_init {
	riscv.embed_tenants("""{
		"streaming": {
			"filename": "/home/gonzo/github/libvmod-riscv/program/cpp/manifest.cpp",
			"arguments": ["change-me-varnish-manifest-secret", "300"]
		}
	}""");
	riscv.finalize_tenants();
}

sub vcl_recv {
	if (!riscv.fork("streaming")) {
		return (synth(503));
	}
	/* A new session for a manifest without a token, an extended one for a
	   manifest with a valid token, or the valid token of anything else */
	set req.http.X-Token = riscv.call("authorize", req.url);
	if (req.http.X-Token !~ "^[A-Za-z0-9_.-]+$") {
		return (synth(403));
	}
	/* The token is per viewer, the cached objects are not */
	set req.url = regsuball(req.url, "(?<=[?&])token=[^&#]*&?", "");
	set req.url = regsub(req.url, "[?&]$", "");
	return (hash);
}

sub vcl_backend_fetch {
	unset bereq.http.X-Token;
}

sub vcl_backend_response {
	if (bereq.url ~ "(?i)\.(m3u8|mpd)(\?|$)") {
		/* deliver_transform needs the plain body */
		set beresp.do_gunzip = true;
	}
}

sub vcl_deliver {
	if (req.url ~ "(?i)\.(m3u8|mpd)(\?|$)" && resp.status == 200) {
		if (!riscv.deliver_transform("personalize", req.http.X-Token)) {
			return (synth(503));
		}
		set resp.http.Cache-Control = "private, no-store";
		set resp.http.X-Viewer-ID = regsub(req.http.X-Token, "\..*$", "");
	}
}
