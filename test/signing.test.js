const test = require('node:test')
const assert = require('node:assert')
const Keypair = require('../lib/index')
const crypto = require('crypto')

test('sign()/verify() does not work on strings', (t) => {
  const str = 'ppppp'
  const keypair = Keypair.generate()
  assert.throws(() => {
    Keypair.sign(keypair, str)
  })
})

test('sign()/verify() a buffer without hmac key', (t) => {
  const buf = Buffer.from('ppppp')
  const keypair = Keypair.generate()
  const sig = Keypair.sign(keypair, buf)
  assert.ok(sig)
  const { public, curve } = keypair
  assert.ok(Keypair.verify({ public, curve }, buf, sig))
})

test('sign()/verify a buffer with hmac key', (t) => {
  const str = Buffer.from('ppppp')
  const keypair = Keypair.generate()
  const hmac_key = crypto.randomBytes(32)
  const hmac_key2 = crypto.randomBytes(32)

  const sig = Keypair.sign(keypair, str, hmac_key)
  assert.ok(sig)
  assert.equal(Keypair.verify(keypair, str, sig, hmac_key), true)
  assert.equal(Keypair.verify(keypair, str, sig, hmac_key2), false)
})
