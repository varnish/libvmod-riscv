vcl 4.1;

import std;
import digest;
import headerplus;
import cookieplus;

acl local {
    "127.0.0.1";
    "::1";
}

var visits: INT = 0;

sub vcl_recv {
    if (client.ip ~ local) {
        set req.http.X-Local = "yes";
    }
    set req.http.X-Upper = std.toupper(req.http.X-Name);
    set req.http.X-Sha = digest.hash_sha256("abc");
    set req.http.X-Mac = digest.hmac_sha256("key", "msg");
    if (digest.verify_hmac_sha256("key", "msg", req.http.X-Mac)) {
        set req.http.X-Mac-Ok = "yes";
    }
    cookieplus.keep("session");
    cookieplus.write();

    headerplus.init_req();
    headerplus.delete_regex("^X-Drop-");
    headerplus.write();

    set var.visits = var.visits + 1;
    return (hash);
}

sub vcl_backend_response {
    set beresp.grace = 10s;
    set beresp.keep = 1m;
    set beresp.http.X-Grace = beresp.grace;
    set beresp.http.X-Ttl = beresp.ttl;
    if (bereq.url ~ "^/uncacheable") {
        set beresp.uncacheable = true;
    }
}

sub vcl_deliver {
    set resp.http.X-Visits = var.visits;
    set resp.http.X-Status = resp.status;
}
