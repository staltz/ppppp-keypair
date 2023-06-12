# ppppp-keypair

Like `ssb-keys`, but for PPPPP.

API:

- `generate(curve?, seed?) => Keypair {curve, public, private}`
- `sign(keypair, msg, hmacKey?) => sig`
- `verify(keypair, msg, sig, hmacKey?) => boolean`
- `create(filepath, cb)`
- `load(filepath, cb)`
- `loadOrCreate(filepath, cb)`
- `createSync(filepath)`
- `loadSync(filepath)`
- `loadOrCreateSync(filepath)`
