---
"@nestm/crypto": minor
---

`AzureKeyVaultProvider` now fails closed on a non-empty wrapping context. Key Vault's
wrapKey/unwrapKey operations accept no AAD or OAEP label, so a key context passed through the
Azure provider was silently dropped instead of authenticated — wrapped keys would unwrap under
any context. Both `generateDataKey` and `unwrapDataKey` now throw a `CONFIGURATION` error
before calling the vault when `wrappingContext` is non-empty; envelopes using the Azure
provider must be written without a key context.
