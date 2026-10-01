sub traffic_router_health {
    if (req.http.Accept == "application/vnd.router.healthcheck+json" &&
        req.http.User-Agent ~ "Varnish Request Router") {
        return (pass);
    }
    return (hash);
}

sub health_backend_response {
    set beresp.do_gzip = true;
    set beresp.http.Content-Type = "application/json";
    set beresp.http.Cache-Control = "no-cache";
    set beresp.ttl = 0.1s;
    set beresp.uncacheable = true;
    return (deliver);
}
