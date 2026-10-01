vcl 4.1;
static var hits: INT = 0;
sub vcl_recv {
    return (hash);
}
