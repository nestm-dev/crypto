---
"@nestm/crypto": minor
---

Derive a one-use AES-256-GCM wrapping key with HKDF-SHA256 and a fresh 256-bit salt for every new
local key-ring data key while retaining read-only compatibility with legacy A256GCMKW envelopes.
Version 2 removes the need for a durable global wrapper-invocation counter and keeps 128-bit
authentication.
