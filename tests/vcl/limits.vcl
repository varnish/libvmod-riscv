vcl 4.1;

import std;

sub vcl_recv {
    if (req.url == "/slow-match") {
        if (req.http.X-Subject ~ "^(a|aa)+$") {
            return (synth(200, "matched"));
        }
        return (synth(404, "not matched"));
    }
    if (req.url == "/slow-regsub") {
        set req.http.X-Out = regsuball(req.http.X-Subject, "(a|aa)+b|.", "x");
        return (synth(200, "replaced"));
    }
    if (req.url == "/log") {
        std.log("[other.com] spoofed");
    }
    if (req.url == "/semantics") {
        return (synth(200, "/semantics"));
    }
    return (synth(200, "ok"));
}

sub vcl_synth {
    if (resp.reason == "/semantics") {
        set resp.http.T-1 = regsuball("aaa", "^a", "b");
        set resp.http.T-2 = regsub("foo-bar", "(\w+)-(\w+)", "\2-\1");
        set resp.http.T-3 = regsuball("abc", "x*", "-");
        set resp.http.T-4 = regsub("abc", "(b)", "[\0\1\9]");
        set resp.http.T-5 = regsuball("a.b.c", "\.", "/");
        set resp.http.T-6 = regsuball("abab", "b", "\\");
    }
    return (deliver);
}
