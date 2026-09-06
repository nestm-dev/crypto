---
"@nestm/crypto": patch
---

Add bounded authenticated NMF1 plaintext range reads over an immutable-object range source. Range reads authenticate the pinned header, selected frames and final totals/EOF without decrypting unrelated file contents.
