# llhttp 9.3.0

Generated C parser and MIT license copied from
https://github.com/nodejs/llhttp/tree/release/v9.3.0
(`include/llhttp.h`, `src/api.c`, `src/http.c`, `src/llhttp.c`, `LICENSE-MIT`).
No Node.js runtime or code generation is needed to build OuterSSH.

Local fix in `llhttp.c`: guard the NEON zero match mask before `__builtin_ctzll`,
whose argument must be nonzero; an all-matching 16-byte block advances by 16.
