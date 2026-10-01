vcl 4.1;

var kind: STRING; # A global per-request variable

sub vcl_recv {
    set req.http.X-Configured-By = "compiled-vcl";
    if (req.url ~ "^/(foo|bar|baz)$") {
        set var.kind = "greeting";
    } else {
        set var.kind = "other";
    }
    if (req.method == "GET") {
        set req.http.X-Original-Method = req.method;
    } else {
        return (pass);
    }
    std.log("compiled VCL received request");
    return (hash);
}

sub vcl_backend_fetch {
    set bereq.http.X-Origin-Policy = "compiled-vcl";
    set bereq.http.X-Request-Kind = var.kind;
    return (fetch);
}

sub vcl_backend_response {
    set beresp.http.X-Cache-Policy = "compiled-vcl";
    if (beresp.status >= 500) {
        set beresp.ttl = 10s;
    } else {
        set beresp.ttl = 1m - 15s * 2;
    }
    return (deliver);
}

sub vcl_deliver {
    set resp.http.X-Delivered-By = "compiled-vcl";
    set resp.http.X-Request-Kind = var.kind;
    return (deliver);
}
