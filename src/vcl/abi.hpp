#pragma once
#include <cstddef>
#include <cstdint>

/**
 * The policy ABI a VCL-compiled tenant program calls, ported from
 * Carapace's scripting ABI.
 *
 * Numbers are Carapace's 490..=510 shifted by 50, so the whole block sits
 * between the VMOD's own API (500..=539, machine/syscalls.h) and the native
 * heap and memory helpers (580.., NATIVE_SYSCALLS_BASE). The compiler's
 * `define_syscalls!` table (vcl/compiler/src/ir.rs) is the other half of
 * this file; a number changed here has to change there.
 *
 * Arguments are in a0..a6 and the result in a0. Strings are (pointer,
 * length) pairs, never NUL-terminated. -1 is a refusal: the generated code
 * either treats it as "absent" or traps at the VCL line that made the call,
 * which fails the VCL subroutine with VRT_fail.
 */
namespace rvs::vcl::abi {

static constexpr unsigned SYS_REQ_GET_METHOD  = 540;
static constexpr unsigned SYS_REQ_GET_URL     = 541;
static constexpr unsigned SYS_REQ_GET_HEADER  = 542;
static constexpr unsigned SYS_REQ_SET_HEADER  = 543;
static constexpr unsigned SYS_REQ_SET_URL     = 544;
static constexpr unsigned SYS_RESP_GET_HEADER = 545;
static constexpr unsigned SYS_RESP_SET_HEADER = 546;
static constexpr unsigned SYS_RESP_GET_STATUS = 547;
static constexpr unsigned SYS_LOG             = 548;
static constexpr unsigned SYS_RETURN_ACTION   = 549;
static constexpr unsigned SYS_SET_TTL         = 551;
static constexpr unsigned SYS_REGEX_MATCH     = 552;
/* Sub-command in a0, arguments from a1. */
static constexpr unsigned SYS_TYPED           = 560;

static constexpr int64_t TYPED_REQ_HEADERS_COMMIT  = 2;
static constexpr int64_t TYPED_RESP_HEADERS_COMMIT = 4;
static constexpr int64_t TYPED_HASH                = 8;
static constexpr int64_t TYPED_SIGN                = 9;
static constexpr int64_t TYPED_VERIFY              = 10;
static constexpr int64_t TYPED_SET_GRACE           = 17;
static constexpr int64_t TYPED_SET_KEEP            = 18;
static constexpr int64_t TYPED_REQ_REMOVE_HEADER   = 19;
static constexpr int64_t TYPED_RESP_REMOVE_HEADER  = 20;
static constexpr int64_t TYPED_SET_OUTCOME_PLAIN   = 21;
static constexpr int64_t TYPED_REGSUB              = 22;
static constexpr int64_t TYPED_HEADERS_SNAPSHOT    = 23;
static constexpr int64_t TYPED_REGEX_MATCH_LIST    = 24;
static constexpr int64_t TYPED_CLIENT_IP           = 26;
static constexpr int64_t TYPED_CACHE_DURATION      = 27;
/* Not part of the policy ABI: the compiler guest's include read, answered
   only while a compile runs on the calling thread (compiler.cpp). */
static constexpr int64_t TYPED_INCLUDE_READ        = 28;
static constexpr int64_t TYPED_CACHE_STATUS        = 31;
/* Varnish variables by number (vclv_var in vcl_varnish.h). */
static constexpr int64_t TYPED_VAR_GET_STRING      = 32;
static constexpr int64_t TYPED_VAR_GET_SCALAR      = 33;
static constexpr int64_t TYPED_VAR_SET_SCALAR      = 34;
static constexpr int64_t TYPED_VAR_SET_STRING      = 35;
static constexpr int64_t TYPED_HASH_DATA           = 36;
static constexpr int64_t TYPED_SYNTH_BODY          = 37;

/* Outcome codes (return_action, set_outcome_plain), the compiler's
   ActionCode. ACTION_NEXT is a hook that ended without a return. */
static constexpr int64_t ACTION_NEXT    = 0;
static constexpr int64_t ACTION_PASS    = 1;
static constexpr int64_t ACTION_DELIVER = 2;
static constexpr int64_t ACTION_SYNTH   = 3;  /* status, reason */
static constexpr int64_t ACTION_ABANDON = 4;
static constexpr int64_t ACTION_HASH    = 5;
static constexpr int64_t ACTION_LOOKUP  = 6;
static constexpr int64_t ACTION_FETCH   = 7;
static constexpr int64_t ACTION_MISS    = 8;
static constexpr int64_t ACTION_ERROR   = 9;  /* status, reason */
static constexpr int64_t ACTION_FAIL    = 10;

static constexpr uint64_t FAILED = UINT64_MAX;
/* A regex the host will not run: distinct from "did not match", because
   the generated code traps on it rather than reading it as false. */
static constexpr uint64_t REGEX_REFUSED = uint64_t(-2);

/* Bounds on what a policy may hand the host. The host's work inside a
   call is not charged to the instruction budget, so every input that
   drives host work is capped. */
static constexpr size_t MAX_HEADERS   = 4096;
static constexpr size_t MAX_NAME      = 1024;
static constexpr size_t MAX_VALUE     = 64 * 1024;
static constexpr size_t MAX_BODY      = 4 * 1024 * 1024;
static constexpr size_t MAX_PATTERN   = 4 * 1024;
static constexpr size_t MAX_SUBJECT   = 256 * 1024;
static constexpr size_t MAX_LIST_BYTES = 1024 * 1024;
static constexpr size_t MAX_CRYPTO_INPUT = 1 << 20;
/* 365 days: a TTL or stale window past it is refused, not clamped, so a
   0 result always means the value was applied. */
static constexpr uint64_t MAX_TTL_SECONDS = 31'536'000;

/* A guest `Vec`/`String` header, as the runtime lays it out. */
struct GuestVec {
	uint64_t cap;
	uint64_t ptr;
	uint64_t len;
};
/* One entry of the vector a header commit passes (vcl-rt's `Header`). */
struct GuestHeader {
	GuestVec name;
	GuestVec value;
	uint8_t  dirty;
	uint8_t  pad[7];
};
static_assert(sizeof(GuestHeader) == 56, "vcl-rt header entry layout");

/* regsub and regex_match_list take a 40-byte descriptor of five u64s. */
static constexpr size_t REGEX_DESCRIPTOR = 40;
static constexpr uint64_t REGEX_LIST_FIELD_VALUE = 1;
static constexpr uint64_t REGEX_LIST_ALL = 1 << 1;

} // rvs::vcl::abi
