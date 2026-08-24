---
"@nestm/crypto": minor
---

Add the optional `@nestm/crypto/storage-workspace` bridge for composing a
capability-scoped `@nestm/storage` workspace with strict, authenticated body
encryption. The bridge keeps storage and crypto policies application-owned,
binds ciphertext to stable workspace scope and canonical path context, exposes
only a non-secret protection descriptor, and leaves the framework-neutral
crypto core independent of storage.
