function on_recv(req) {
	return ["synth", 202];
}
function on_synth(req, resp) {
	resp.set("X-Script", "updated.js");
}
