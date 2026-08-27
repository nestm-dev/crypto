---
"@nestm/crypto": minor
---

Remove the storage-specific `@nestm/crypto/storage-workspace` integration and
its optional `@nestm/storage` peer. Applications now compose storage policy,
artifact record formats, authenticated path context, and searchable projections
from the generic primitives exposed by `@nestm/crypto/core`.
