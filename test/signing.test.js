const test = require('node:test')
const assert = require('node:assert')
const TextEncoder = require('node:util').TextEncoder
const Keypair = require('../lib/index')
const crypto = require('crypto')

test('sign()/verify() does not work on strings', (t) => {
  const str = 'ppppp'
  const keypair = Keypair.generate()
  assert.throws(() => {
    Keypair.sign(keypair, str)
  })
})

test('sign()/verify() a uint8arr without hmac key', (t) => {
  const bytes = (new TextEncoder()).encode('ppppp')
  const keypair = Keypair.generate()
  const sig = Keypair.sign(keypair, bytes)
  assert.ok(sig)
  const { public, curve } = keypair
  assert.ok(Keypair.verify({ public, curve }, bytes, sig))
})

test('sign()/verify a uint8arr with hmac key', (t) => {
  const bytes = (new TextEncoder()).encode('ppppp')
  const keypair = Keypair.generate()
  const hmac_key = crypto.randomBytes(32)
  const hmac_key2 = crypto.randomBytes(32)

  const sig = Keypair.sign(keypair, bytes, hmac_key)
  assert.ok(sig)
  assert.equal(Keypair.verify(keypair, bytes, sig, hmac_key), true)
  assert.equal(Keypair.verify(keypair, bytes, sig, hmac_key2), false)
})
