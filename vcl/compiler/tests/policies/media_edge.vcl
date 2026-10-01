vcl 4.1;

# digest is part of Carapace VCL's standard API. This compatibility import is
# deliberately a no-op and may be removed without changing the policy.
import digest;

# This is the VCL counterpart to carapace-guest/examples/media_edge.rs. The
# token is the lowercase hex HMAC-SHA256 of the exact request URL. Replace both
# example keys before use; keep the previous key only for a rotation window.

# Set once in vcl_recv; each origin fetch starts from a copy, so
# vcl_backend_response reads the answer instead of matching the URL again.
var is_manifest: BOOL;

sub vcl_recv {
    if (req.method == "PURGE") {
        return (hash);
    }
    if (req.url ~ "\\?") {
        return (synth(400, "query strings are not supported"));
    }
    if (req.url !~ "^/vod/[^/]+/.+\\.(m3u8|mpd|m4s|mp4|m4a|ts)$") {
        return (synth(404, "not found"));
    }

    if (req.method == "OPTIONS") {
        if (req.http.Origin == "" ||
            (req.http.Access-Control-Request-Method != "GET" &&
             req.http.Access-Control-Request-Method != "HEAD") ||
            req.http.Access-Control-Request-Headers !~
                "^(|[Xx]-[Pp]lay-[Tt]oken|[Rr]ange|[Xx]-[Pp]lay-[Tt]oken, ?[Rr]ange|[Rr]ange, ?[Xx]-[Pp]lay-[Tt]oken)$") {
            return (synth(403, "forbidden"));
        }
        return (pass);
    }
    if (req.method != "GET" && req.method != "HEAD") {
        return (synth(405, "method not allowed"));
    }

    var token_is_valid: bool =
        digest.verify_hmac_sha256(
            "replace-with-random-secret-at-least-32-bytes",
            req.url,
            req.http.X-Play-Token) ||
        digest.verify_hmac_sha256(
            "previous-random-secret-at-least-32-bytes",
            req.url,
            req.http.X-Play-Token);
    if (!var.token_is_valid) {
        return (synth(403, "forbidden"));
    }
    set var.is_manifest = req.url ~ "\\.(m3u8|mpd)$";
    if (req.http.Range != "") {
        return (pass);
    }
    return (hash);
}

sub vcl_backend_fetch {
    # Remove the credentials outright: an empty value is still a header the
    # origin sees, and an empty Cookie or Authorization is observably
    # different from its absence.
    unset bereq.http.X-Play-Token;
    unset bereq.http.Cookie;
    unset bereq.http.Authorization;
    set bereq.http.Accept-Encoding = "identity";
    set bereq.http.X-Carapace-Fetch = "1";
    return (fetch);
}

sub vcl_backend_response {
    # Deliver, but do not store. `return (abandon)` would be wrong here: it
    # discards the response the client is waiting for and answers from the
    # stale-if-error path instead. What this route means is "this one is not
    # cacheable", which is `beresp.uncacheable`.
    if (bereq.method == "OPTIONS" ||
        beresp.http.Set-Cookie != "" ||
        beresp.http.Vary != "") {
        set beresp.uncacheable = true;
        return (deliver);
    }
    if (beresp.status == 200) {
        if (beresp.http.Cache-Control == "") {
            if (var.is_manifest) {
                set beresp.ttl = 1m;
            } else {
                set beresp.ttl = 1d;
            }
        }
        var url_digest: string = digest.hash_sha256(bereq.url);
        set beresp.http.Y-Key = var.url_digest;
        if (!var.is_manifest && beresp.http.ETag == "") {
            # Origin validators are preserved; only an undated asset gets a
            # synthesized one. A bare digest is not a syntactically valid
            # validator, so wrap it as a weak ETag.
            set beresp.http.ETag = "W/\"" + var.url_digest + "\"";
        }
        return (deliver);
    }
    if (beresp.status == 304) {
        return (deliver);
    }
    if (beresp.status == 404 || beresp.status == 410) {
        if (beresp.http.Cache-Control == "") {
            set beresp.ttl = 5s;
        }
        return (deliver);
    }
    # An origin failure is the one case worth discarding: within the route's
    # `keep` the client gets the last good segment instead of the 5xx, and
    # without one it gets a 503. Everything else is delivered uncached rather
    # than thrown away — a 301 the client asked for is not a fetch failure.
    if (beresp.status >= 500) {
        return (abandon);
    }
    set beresp.uncacheable = true;
    return (deliver);
}

sub vcl_deliver {
    set resp.http.X-Content-Type-Options = "nosniff";
    if (req.method == "OPTIONS" &&
        (resp.status == 204 ||
         (resp.status == 200 && resp.http.Content-Length == "0"))) {
        set resp.http.Access-Control-Allow-Origin = "*";
        set resp.http.Access-Control-Allow-Methods = "GET, HEAD, OPTIONS";
        set resp.http.Access-Control-Allow-Headers = "X-Play-Token, Range";
        set resp.http.Access-Control-Max-Age = "600";
    } else {
        set resp.http.Access-Control-Allow-Origin = "*";
        set resp.http.Access-Control-Expose-Headers =
            "Accept-Ranges, Content-Length, Content-Range, ETag";
    }
    return (deliver);
}
