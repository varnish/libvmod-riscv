vcl 4.1;

sub vcl_recv {
    if (req.url == "/fail") {
        return (fail);
    }
    if (req.url ~ "^/old/") {
        set req.url = regsub(req.url, "^/old/", "/new/");
    }
    if (req.url == "/moved") {
        return (synth(750, "/new/place"));
    }
    if (req.url ~ "^/private") {
        return (pass);
    }
    set req.http.X-Method = req.method;
    # An explicit hash skips Varnish's built-in vcl_recv, which would pass
    # a request with a Cookie.
    return (hash);
}

sub vcl_hash {
    # The query string is not part of the key.
    hash_data(regsub(req.url, "\?.*$", ""));
    return (lookup);
}

sub vcl_hit {
    set req.http.X-Hits = obj.hits;
    return (deliver);
}

sub vcl_miss {
    set req.http.X-Miss = "yes";
    return (fetch);
}

sub vcl_pass {
    set req.http.X-Pass = "yes";
    return (fetch);
}

sub vcl_backend_fetch {
    set bereq.http.X-Fetch-Url = bereq.url;
    return (fetch);
}

sub vcl_backend_response {
    if (beresp.status == 500) {
        return (error(502, "origin failed"));
    }
    if (bereq.url == "/rewrite-status") {
        set beresp.status = 203;
        set beresp.reason = "Rewritten";
    }
    set beresp.http.X-Origin-Proto = beresp.proto;
    set beresp.ttl = 1m;
    return (deliver);
}

sub vcl_backend_error {
    set beresp.http.Content-Type = "text/plain";
    set beresp.http.X-Error = beresp.reason;
    synthetic("backend error " + beresp.status);
    return (deliver);
}

sub vcl_deliver {
    set resp.http.X-Hits = req.http.X-Hits;
    set resp.http.X-Miss = req.http.X-Miss;
    set resp.http.X-Pass = req.http.X-Pass;
    if (req.xid != "") {
        set resp.http.X-Has-Xid = "yes";
    }
    if (req.url == "/teapot") {
        set resp.status = 418;
        set resp.reason = "Teapot";
    }
    return (deliver);
}

sub vcl_synth {
    if (resp.status == 750) {
        set resp.http.Location = resp.reason;
        set resp.status = 301;
        set resp.reason = "Moved Permanently";
        return (deliver);
    }
}
