vcl 4.1;

# Same name and kind as stats.vcl: the counter carries on.
static var requests: INT stat "Requests the tenant saw";
# No request changes it, yet the word has held 100.
static var peak: INT = 100 stat max;

sub vcl_recv {
    set var.requests += 10;
    return (synth(204, "updated"));
}
