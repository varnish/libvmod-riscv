sub tag_request {
    set req.http.X-Policy = "edge";
    if (req.http.Cookie) {
        set req.http.X-Has-Cookie = "yes";
    }
}
