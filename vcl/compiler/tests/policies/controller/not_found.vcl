vcl 4.1;
sub vcl_recv { return (synth(404)); }
sub vcl_synth {
    unset resp.http.Server;
    unset resp.http.X-Varnish;
    return (deliver);
}
