---
"@nestm/crypto": minor
---

Derive a one-use AES-256-GCM wrapping key with HKDF-SHA256 and a fresh 256-bit salt for every local
key-ring data key. Version 2 removes the need for a durable global wrapper-invocation counter and
keeps 128-bit authentication.
