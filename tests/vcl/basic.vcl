vcl 4.1;

include "lib/tagging.vcl";

var kind: STRING;

sub vcl_recv {
    if (req.url ~ "^/deny") {
        return (synth(403, "denied"));
    }
    if (req.url == "/gone") {
        return (synth(404));
    }
    if (req.url ~ "^/api/") {
        set var.kind = "api";
    }
    call tag_request;
    if (req.url == "/pass") {
        return (pass);
    }
    return (hash);
}

sub vcl_synth {
    set resp.http.Content-Type = "text/plain";
    set resp.http.X-Synth = "policy";
    synthetic("nope");
    return (deliver);
}

sub vcl_backend_fetch {
    set bereq.http.X-Fetch = "vcl";
    set bereq.url = regsub(bereq.url, "^/old/", "/new/");
}

sub vcl_backend_response {
    set beresp.http.X-Cache-Policy = "vcl";
    set beresp.http.X-Origin = beresp.http.Server;
    unset beresp.http.Server;
    set beresp.ttl = 30s;
}

sub vcl_deliver {
    set resp.http.X-Delivered-By = "vcl";
    set resp.http.X-Kind = var.kind;
    if (req.cache_hit) {
        set resp.http.X-Hit = "1";
    } else {
        set resp.http.X-Hit = "0";
    }
    if (req.url == "/teapot") {
        return (synth(418, "teapot"));
    }
}
