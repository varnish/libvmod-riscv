mod sysalloc;
mod varnish;
use common_access_token::{Algorithm, KeyId, RegisteredClaims, TokenBuilder, VerificationOptions};
use common_access_token::current_timestamp;
use varnish::*;

// The secret key used for signing and verifying tokens
const SECRET_KEY: &[u8] = b"my-secret-key-for-hmac-sha256";

fn on_client_request(_a: u32, _b: u32) {
	let url = get_url();
	add_req_header("X-Hello", &get_url());

	if url == "/verify" {
		forge_with_post(CachingDecision::Uncached, |_a: u32, _b: u32, data: &[u8]| {
			if data.len() == 0 {
				// We can return a response, but also through a function call (faster)
				backend_response(400, "text/plain", b"No token provided");
			}
			// Decode and verify the token
			let decoded_token = common_access_token::Token::from_bytes(data)
				.expect("Failed to decode token");

			// Verify the signature
			decoded_token.verify(SECRET_KEY).expect("Failed to verify signature");

			// Verify the claims
			let options = VerificationOptions::new()
				.verify_exp(true)
				.expected_issuer("example-issuer");
			decoded_token.verify_claims(&options).expect("Failed to verify claims");

			BackendResponse {
				status: 200,
				content_type: "text/plain",
				body: "Token is valid".as_bytes().to_vec(),
			}
		});
	}
	else if url.contains("/cat") {
		forge(CachingDecision::Uncached, |_a: u32, _b: u32| {
			let now = current_timestamp();

			// Create a token
			let token = TokenBuilder::new()
				.algorithm(Algorithm::HmacSha256)
				.protected_key_id(KeyId::string("example-key-id"))
				.registered_claims(
					RegisteredClaims::new()
						.with_issuer("example-issuer")
						.with_subject("example-subject")
						.with_audience("example-audience")
						.with_expiration(now + 3600) // 1 hour from now
				)
				.custom_string(100, "custom-value")
				.sign(SECRET_KEY)
				.expect("Failed to sign token");

			// Encode token to bytes
			let token_bytes = token.to_bytes().expect("Failed to encode token");

			// Decode and verify the token
			let decoded_token = common_access_token::Token::from_bytes(&token_bytes)
				.expect("Failed to decode token");

			// Verify the signature
			decoded_token.verify(SECRET_KEY).expect("Failed to verify signature");

			// Verify the claims
			let options = VerificationOptions::new()
				.verify_exp(true)
				.expected_issuer("example-issuer");

			decoded_token.verify_claims(&options).expect("Failed to verify claims");

			BackendResponse {
				status: 200,
				content_type: "application/cbor",
				body: token_bytes,
			}
		});
	}

	forge(CachingDecision::Cached, |_a: u32, _b: u32| {
		backend_response(200, "text/plain", b"Default response from Rust");
	});
}

fn on_deliver(_a: u32, _b: u32) {
	add_resp_header("X-Delivered-By", "Rust");
	add_full_resp_header(get_req_header("X-Hello").as_str());
}

pub fn main() {
	println!("RISC-V Rust example program started");
	set_on_deliver(on_deliver);
	wait_for_requests(on_client_request);
}
