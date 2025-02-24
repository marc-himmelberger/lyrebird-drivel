The okems package provides various KEMs obfuscated with the keygen-
encapsulate-then-encode construction from
https://eprint.iacr.org/2024/1086.pdf.

Except for x25519ell2, these obufscated KEMs are wrappers around
open-quantum-safe implementations. An encoding defined here takes care
of mapping between obfuscated public keys and ciphertexts and the
corresponding values used for the underlying KEM operations.

Consumers such as the pq_obfs transport should only interface with OKEMs.
