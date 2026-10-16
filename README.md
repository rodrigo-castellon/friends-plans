# Friends Plans
Friends tell Rodrigo where they'll be. Fully static (GitHub Pages).
- Submissions are **end-to-end encrypted in the browser** (RSA-OAEP + AES-GCM) with Rodrigo's public key, posted to an ntfy.sh relay, and archived every 10 min into `data/msgs.jsonl` by a GitHub Action. Only ciphertext is ever stored; the private key exists only in Rodrigo's admin link.
- Friends get a personal edit link (`#t=<token>`); a newer submission with the same token supersedes the old one.
