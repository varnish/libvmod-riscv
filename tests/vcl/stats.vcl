vcl 4.1;

import std;

# Each one is a Varnish counter named RISCV.<tenant>.<name>.
static var requests: INT stat "Requests the tenant saw";
static var inflight: INT stat gauge "Requests between recv and deliver";
static var fetches: INT stat;
static var largest: INT stat max "Largest X-Size seen";
static var smallest: INT stat min "Smallest X-Size seen";
# An initializer is where every request starts, not a count.
static var offset: INT = 100 stat;

sub vcl_recv {
    set var.requests += 1;
    set var.inflight += 1;
    set var.largest = std.integer(req.http.X-Size, 0);
    set var.smallest = std.integer(req.http.X-Size, 0);
    set var.offset += 2;
    # Each request runs in its own fork, so it reads only its own changes.
    set req.http.X-Seen = var.requests;
    set req.http.X-Offset = var.offset;
    return (hash);
}

sub vcl_backend_response {
    set var.fetches += 1;
}

sub vcl_deliver {
    set var.inflight -= 1;
    set resp.http.X-Seen = req.http.X-Seen;
    set resp.http.X-Offset = req.http.X-Offset;
}
