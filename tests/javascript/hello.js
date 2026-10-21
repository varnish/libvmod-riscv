function on_recv(req) {
	if (req.url == "/missing") return ["synth", 404];
	return ["synth", 200];
}
function on_synth(req, resp) {
	resp.set("X-Script", "hello.js");
}
