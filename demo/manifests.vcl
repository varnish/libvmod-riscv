vcl 4.1;
import riscv;
import std;
import vsthrottle;

/* Per-viewer HLS and DASH manifests from one cached copy.
   Start the origin in demo/streams: python3 -m http.server 8081
   The tenant reloads with the updated contents when manifests/settings.json
   or manifests/revoked.txt changes while Varnish is running. */
backend default {
	.host = "127.0.0.1";
	.port = "8081";
}

sub vcl_init {
	riscv.embed_tenants("""{
		"streaming": {
			"filename": "/home/gonzo/github/libvmod-riscv/program/cpp/manifest.cpp",
			"config_files": {
				"settings": "/home/gonzo/github/libvmod-riscv/demo/manifests/settings.json",
				"revocations": "/home/gonzo/github/libvmod-riscv/demo/manifests/revoked.txt"
			}
		}
	}""");
	riscv.finalize_tenants();
}

sub vcl_recv {
	if (!riscv.fork("streaming")) {
		return (synth(503));
	}
	/* Start a session for a manifest request with an entitlement (auth),
	   or validate the request's existing token. */
	set req.http.X-Client-IP = client.ip;
	set req.http.X-Token = riscv.call("authorize", req.url);
	if (req.http.X-Token !~ "^[A-Za-z0-9_.-]+$") {
		return (synth(403));
	}
	set req.http.X-Subscriber = regsub(req.http.X-Token, "^[^.]+\.([^.]+)\..*$", "\1");
	set req.http.X-Session = regsub(req.http.X-Token, "^[^.]+\.[^.]+\.([^.]+)\..*$", "\1");
	/* Limit new sessions per subscriber and the request rate per session. */
	if (req.url !~ "[?&]token=" && vsthrottle.is_denied("start:" + req.http.X-Subscriber, 5, 10m)) {
		return (synth(429));
	}
	if (vsthrottle.is_denied("rate:" + req.http.X-Session, 600, 60s)) {
		return (synth(429));
	}
	std.log("viewer " + req.http.X-Subscriber + " " + req.http.X-Session);
	/* Select an A/B variant for each video segment for forensic watermarking. */
	if (req.url ~ "^/live/[^/]+/(low|high)/seg[0-9]+\.m4s") {
		set req.http.X-Variant = riscv.call("watermark", req.http.X-Token);
	}
	/* Remove session credentials before looking up the shared cache object. */
	set req.url = regsuball(req.url, "(?<=[?&])(token|auth)=[^&#]*&?", "");
	set req.url = regsub(req.url, "[?&]$", "");
	if (req.http.X-Variant ~ "^[AB]$") {
		set req.url = regsub(req.url, "^(.*/)([^/?]+)", "\1" + req.http.X-Variant + "/\2");
	}
	return (hash);
}

sub vcl_backend_fetch {
	unset bereq.http.X-Token;
	unset bereq.http.X-Client-IP;
	unset bereq.http.X-Subscriber;
	unset bereq.http.X-Session;
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
		set resp.http.X-Viewer-ID = req.http.X-Session;
	}
}
