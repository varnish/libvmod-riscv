#pragma once
#include <string>

namespace api
{
	enum Cache {
		NotCached = 0,
		Cached = 1,
	};

	enum gethdr_e {
		HDR_REQ = 0,
		HDR_REQ_TOP,
		HDR_RESP,
		HDR_OBJ,
		HDR_BEREQ,
		HDR_BERESP
	};

	struct HeaderField;
	struct Regex;

	inline long double operator ""_s(long double x) {
		return x;
	}
	inline long double operator ""_m(long double x) {
		return x * 60.0;
	}
	inline long double operator ""_h(long double x) {
		return x * 3600.0;
	}

	template <class T>
	struct IsType {
	    static std::true_type test(const T&);

	    static std::false_type test(...);

	    template <class V, class... Further>
	    static constexpr bool value = (
	        (sizeof...(Further) == 0) &&
	        decltype(test(std::declval<V>()))::value
	    );
	};

	__attribute__((noreturn))
	inline void forge_response(uint16_t status,
		const char* arg0, size_t arg1, const char* arg2, size_t arg3)
	{
		register long        a0 asm("a0") = status;
		register const char* a1 asm("a1") = (const char*)arg0;
		register size_t      a2 asm("a2") = arg1;
		register const char* a3 asm("a3") = (const char*)arg2;
		register size_t      a4 asm("a4") = arg3;

		asm volatile (".insn i SYSTEM, 0, a0, x0, 0x7ff"
		  : : "m"(*(const char(*)[arg1]) a1),
			  "m"(*(const char(*)[arg3]) a3),
			  "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4));
		__builtin_unreachable();
	}

	struct response {
		response(uint16_t s, const std::string& mimetype, std::string_view data) {
			forge_response(s, mimetype.c_str(), mimetype.size(), data.begin(), data.size());
		}
		response(uint16_t s, const std::string& mimetype, const std::vector<uint8_t>& data) {
			forge_response(s, mimetype.c_str(), mimetype.size(), (const char *)data.data(), data.size());
		}
	};

	struct serializer {
		serializer(const void* data, size_t len) {
			register const char* a0 asm("a0") = (const char*)data;
			register size_t      a1 asm("a1") = len;

			asm volatile (".insn i SYSTEM, 0, %0, x0, 0x7ff"
				: "+r"(a0)
				: "m"(*(const char(*)[len]) a0), "r"(a1));
		}
		template <typename T>
		serializer(const T& object)
			: serializer(&object, sizeof(object)) {}
		serializer()
			: serializer(nullptr, 0) {}
	};
	struct serialized {
		const void* data;
		const size_t len;

		template <typename T>
		const T& view_as() const noexcept {
			return *(const T*) data;
		}

		template <typename T>
		void copy_to(T& obj) const noexcept {
			obj = *(const T*) data;
		}
	};
}

#define pub(x, ...) extern "C" __attribute__((used, retain)) void x(__VA_ARGS__)
#define pubr(r, x) extern "C" __attribute__((used, retain)) r x()
