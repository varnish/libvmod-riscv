vcl 4.1;

# New, and valid on its own: refused with the program, it is never published.
static var leaked: INT stat;
# stats.vcl counts requests as a counter.
static var requests: INT stat gauge;

sub vcl_recv {
    return (synth(204, "kind"));
}
