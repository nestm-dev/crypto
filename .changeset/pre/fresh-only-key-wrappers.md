---
"@nestm/crypto": minor
---

Make the local AES key ring fresh-format only: unwrap accepts exactly the 81-byte salted version 2
wrapper and its `NESTM-A256GCM-HKDF-SHA256-SALT256-V2` identifier. Remove the deprecated version 1
algorithm export and compatibility path; development data using another wrapper format must be reset.
