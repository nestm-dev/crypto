---
"@nestm/crypto": minor
---

Add tenant-aware text batches, typed value codecs, explicit NestJS HTTP field adapters, and a
schema-agnostic Prisma write-encryption processor. Existing ciphertext is authenticated before
idempotent writes, batch resources are bounded, and the new persistence APIs never accept plaintext
data-encryption keys.
