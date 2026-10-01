vcl 4.1;
import file;
backend default { .host = "0:0"; }
sub vcl_init { new acme = file.init("/var/lib/agent/acme"); }
sub vcl_recv { return (synth(404)); }
sub vcl_synth { unset resp.http.Server; unset resp.http.X-Varnish; return (deliver); }
