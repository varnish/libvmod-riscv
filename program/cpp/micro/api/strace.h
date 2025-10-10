//#define VERBOSE_COMMANDS
#ifdef VERBOSE_COMMANDS
static constexpr bool verbose_commands = true;

PPT() inline void strace(Args&&... args) {
	if constexpr (verbose_commands) {
		print("[trace] ", std::forward<Args> (args)...);
	}
}
#else
static constexpr bool verbose_commands = false;
#define strace(...) /* */

#endif


__attribute__((const))
inline const char* wstr(gethdr_e where) {
	switch (where) {
		case HDR_REQ: return "REQ";
		case HDR_RESP: return "RESP";
		case HDR_BEREQ: return "BEREQ";
		case HDR_BERESP: return "BERESP";
		default: return "INVALID";
	}
}

#define HFIDX(x) (x != UINT32_MAX ? std::to_string(x) : "INVALID")
