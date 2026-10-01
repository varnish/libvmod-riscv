vcl 4.1;
sub vcl_recv {
    set req.http.X-Agent-Name = "agent-1";
    set req.http.X-VCLGroup-Name = "api";
    return (hash);
}
