vcl 4.1;
sub vcl_recv {
    return (synth(204, "updated"));
}
