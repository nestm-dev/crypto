---
"@nestm/crypto": minor
---

Add the cloud-neutral `@nestm/crypto/files` entry point and NMF1 streaming file encryption. The
format uses fresh per-file data keys, fixed 1 MiB authenticated frames, a mandatory authenticated
final frame and physical-EOF check, detached wrapped-key records, bounded backpressure-aware Web
streams, and exact context/header/size/hash verification. Deterministic conformance vectors use an
isolated fixture provider; production providers continue to use the platform CSPRNG.
