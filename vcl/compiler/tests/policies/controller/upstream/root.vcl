vcl 4.1;
import file;
import std;
import accounting;
import urlplus;
import headerplus;

backend default { .host = "0:0"; }
include "traffic_router_health.vcl";

sub vcl_init {
    accounting.create_namespace("vg_7");
    new acme = file.init("/var/lib/agent/acme");
}

sub vcl_recv {
    if (req.url ~ "^/\\.well-known/acme-challenge/") {
        set req.backend_hint = acme.backend();
        return (pass);
    }
    set req.http.X-VController-HostNoPort = std.tolower(regsub(req.http.Host, ":[0-9]+", ""));
    if (req.http.X-VController-HostNoPort == "base.example") {
        set req.http.X-VController-HostNoPort = urlplus.url_get(0, 0);
        set req.http.host = std.tolower(req.http.X-VController-HostNoPort);
        set req.http.X-Routed-For = "base.example:8080";
        urlplus.url_delete_range(0, 0);
        urlplus.write();
    }
    set req.http.X-Agent-Name = "agent-1";
    if (req.http.X-VController-HostNoPort == "shop.example.com") {
        unset req.http.X-VController-HostNoPort;
        set req.http.X-VCLGroup-Name = "shop";
        accounting.set_namespace("vg_7");
        accounting.add_keys("dom_31");
        headerplus.init(req);
        headerplus.write_req0();
        return (vcl(label-7));
    }
    return (synth(404));
}

sub vcl_synth {
    unset resp.http.Server;
    unset resp.http.X-Varnish;
    return (deliver);
}
