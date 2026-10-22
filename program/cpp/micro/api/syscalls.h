#pragma once
#define SYSCALL_BASE 500

#define ECALL_FAIL (SYSCALL_BASE+0)
#define ECALL_ASSERT_FAIL (SYSCALL_BASE+1)
#define ECALL_PRINT (SYSCALL_BASE+2)
#define ECALL_WRITE  ECALL_PRINT
#define ECALL_LOG (SYSCALL_BASE+3)
#define ECALL_BREAKPOINT (SYSCALL_BASE+4)
#define ECALL_SIGNAL (SYSCALL_BASE+5)
#define ECALL_IS_STORAGE (SYSCALL_BASE+6)
#define ECALL_REMOTECALL (SYSCALL_BASE+7)
#define ECALL_REMSTRCALL (SYSCALL_BASE+8)

#define ECALL_REGISTER_CB (SYSCALL_BASE+9)
#define ECALL_SET_DECISION (SYSCALL_BASE+10)
#define ECALL_SET_BACKEND (SYSCALL_BASE+11)
#define ECALL_BACKEND_DECISION (SYSCALL_BASE+12)
#define ECALL_BAN (SYSCALL_BASE+13)
#define ECALL_HASH_DATA (SYSCALL_BASE+14)
#define ECALL_PURGE (SYSCALL_BASE+15)
#define ECALL_SYNTH (SYSCALL_BASE+16)
#define ECALL_CACHEABLE (SYSCALL_BASE+17)
#define ECALL_TTL (SYSCALL_BASE+18)

#define ECALL_FOREACH_FIELD (SYSCALL_BASE+19)
#define ECALL_FIELD_GET (SYSCALL_BASE+20)
#define ECALL_FIELD_RETRIEVE (SYSCALL_BASE+21)
#define ECALL_FIELD_APPEND (SYSCALL_BASE+22)
#define ECALL_FIELD_SET (SYSCALL_BASE+23)
#define ECALL_FIELD_COPY (SYSCALL_BASE+24)
#define ECALL_FIELD_UNSET (SYSCALL_BASE+25)

#define ECALL_HTTP_ROLLBACK (SYSCALL_BASE+26)
#define ECALL_HTTP_COPY (SYSCALL_BASE+27)
#define ECALL_HTTP_SET_STATUS (SYSCALL_BASE+28)
#define ECALL_HTTP_UNSET_RE (SYSCALL_BASE+29)
#define ECALL_HTTP_FIND (SYSCALL_BASE+30)

#define ECALL_REGEX_COMPILE (SYSCALL_BASE+31)
#define ECALL_REGEX_MATCH (SYSCALL_BASE+32)
#define ECALL_REGEX_SUBST (SYSCALL_BASE+33)
#define ECALL_REGSUB_HDR (SYSCALL_BASE+34)
#define ECALL_REGEX_FREE (SYSCALL_BASE+35)

#define ECALL_SHA256 (SYSCALL_BASE+36)
#define ECALL_FIELD_RETRIEVE_STR (SYSCALL_BASE+37)
#define ECALL_BASE64_DECODE (SYSCALL_BASE + 38)
#define ECALL_REGISTER_FUNC (SYSCALL_BASE + 39)

/* The VCL policy ABI is at 540..560 (src/vcl/abi.hpp) */
#define ECALL_LAST (SYSCALL_BASE+40)

#define ECALL_BASE64 (SYSCALL_BASE+70)
#define BASE64_FLAG_DECODE 0x1
#define BASE64_FLAG_URL    0x2
#define BASE64_FLAG_NOPAD  0x4

/* Outgoing HTTP(S), Varnish Enterprise only (libcurv). The operation is in
   the low byte of a0 and its flags above it:
     GET:  a1,a2 = URL  a3,a4 = request headers ("Name: value" lines)
     POST: GET + a5,a6 = request body
           -> a handle, or a negative FETCH_E*. Redirects are followed
           as the tenant's "max_redirects" allows, under the same handle.
     WAIT: a1 = int32_t handles[]  a2 = count
           a3 = struct fetch_response[count]  a4 = timeout in ms (<0: none)
           -> the number of handles it completed. A completed handle is set
           to -1 and its response filled in; body and headers are on the
           native heap (sys_free() them).
     FREE: a1 = handle: abandon the request.
   struct fetch_response {
       int32_t status;  // HTTP status, 0 when the transfer failed
       int32_t error;   // CURLcode, 0 is success
       char*   body;    size_t body_len;     // NUL-terminated
       char*   headers; size_t headers_len;  // "Name: value\n" lines
   }; */
#define ECALL_FETCH (SYSCALL_BASE+71)
#define FETCH_GET   0
#define FETCH_POST  1
#define FETCH_WAIT  2
#define FETCH_FREE  3
#define FETCH_OP_MASK        0xFF
#define FETCH_FLAG_INSECURE  0x100 /* GET/POST: accept any TLS certificate */
#define FETCH_FLAG_ANY       0x100 /* WAIT: return when any handle is done */
#define FETCH_EINVAL  (-1) /* Bad arguments, or unknown handle */
#define FETCH_EACCES  (-2) /* URL not allowed for this tenant */
#define FETCH_ELIMIT  (-3) /* Too many requests in this task */
#define FETCH_EBUSY   (-4) /* The HTTP engine is out of capacity */
#define FETCH_ENOSYS  (-5) /* Not available in this Varnish */
#define FETCH_EPENDING (-6) /* Not finished (the guest API's FetchResponse) */

/* a0,a1 = the name of a backend in the tenant's "backends"
   a2 = 0 -> its index for ECALL_SET_BACKEND, or -1
   a2 = 1 -> also selects it, as ECALL_SET_BACKEND: 0, or -1 */
#define ECALL_FIND_BACKEND (SYSCALL_BASE+72)
