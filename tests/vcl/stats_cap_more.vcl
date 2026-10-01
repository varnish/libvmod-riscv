vcl 4.1;

# One name past the cap, once stats_cap.vcl has published its 64.
static var one_more: INT stat;

sub vcl_recv {
    return (synth(200));
}
