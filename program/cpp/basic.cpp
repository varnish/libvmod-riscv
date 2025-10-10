#include <api.h>
#include <nlohmann/json.hpp>
#include <tinyxml2.h>
namespace varnish = api;
static varnish::Regex regex("riscv"); // matches the word "riscv"

static void on_recv(varnish::Request req)
{
	const auto url = req.url();
	static constexpr bool USE_FORMATTED = false;
	if constexpr (USE_FORMATTED) {
		req.appendf("X-Hello: url={}", url);
	} else {
		req.append("X-Hello: url=" + url);
	}
	const bool match = regex.match(url) > 0;
	if constexpr (USE_FORMATTED) {
		req.appendf("X-Match: {}", match ? "true" : "false");
	} else {
		req.append("X-Match: " + std::string(match ? "true" : "false"));
	}

	//varnish::hash_data(url);

	forge(varnish::Cached, [] (varnish::Request bereq, varnish::Response beresp, void* body_ptr, size_t body_size) -> varnish::response {
		beresp.append(bereq["X-Tenant"]);

		if constexpr (false) {
			// Create a simple JSON response
			nlohmann::json json;
			json["message"] = "Hello RISC-V World!";
			return varnish::response{200, "application/json", json.dump()};
		}
		// Create simple XML response
		tinyxml2::XMLDocument doc;
		auto* root = doc.NewElement("response");
		if (body_size == 0)
		{
			doc.InsertFirstChild(root);
			auto* msg = doc.NewElement("message");
			msg->SetText("Hello RISC-V World!");
			root->InsertEndChild(msg);
		}
		else
		{
			// Dash XML example from POST body
			doc.Parse(static_cast<const char*>(body_ptr), body_size);
			if (doc.Error())
			{
				doc.Clear();
				doc.InsertFirstChild(root);
				auto* err = doc.NewElement("error");
				err->SetText("Failed to parse XML");
				root->InsertEndChild(err);
			}
			else
			{
				// Modify representation1 video bandwidth
				auto* mpd = doc.FirstChildElement("MPD");;
				if (mpd)
				{
					auto* period = mpd->FirstChildElement("Period");
					if (period)
					{
						auto* adapSet = period->FirstChildElement("AdaptationSet");
						if (adapSet)
						{
							auto* representation = adapSet->FirstChildElement("Representation");
							while (representation)
							{
								const char* id = representation->Attribute("id");
								if (id && std::string(id) == "video1")
								{
									representation->SetAttribute("bandwidth", "12345678");
									break;
								}
								representation = representation->NextSiblingElement("Representation");
							}
						}
					}
				}
			}
		}
		tinyxml2::XMLPrinter printer;
		doc.Print(&printer);
		return varnish::response{200, "application/xml", printer.CStr()};
	});
}

static void on_deliver(varnish::Request req, varnish::Response resp)
{
	resp.append("X-Goodbye: RISCV");
	resp.append(req["X-Hello"]);
	resp.append(req["X-Match"]);
}

int main(int, char** argv)
{
	varnish::print("{} main entered{}\n{}\n",
		varnish::is_storage() ? "Storage" : "Request",
		(varnish::is_debug() ? " (debug)" : ""),
		argv[1]);
	varnish::set_on_deliver(on_deliver);
	varnish::wait_for_requests(on_recv);
}
