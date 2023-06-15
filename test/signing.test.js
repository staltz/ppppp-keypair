const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const b4a = require('b4a')
const Keypair = require('../lib/index')

test('sign()/verify() does not work on strings', (t) => {
  const str = 'ppppp'
  const keypair = Keypair.generate()
  assert.throws(() => {
    Keypair.sign(keypair, str)
  })
})

test('sign()/verify() a buffer without hmac key', (t) => {
  const buf = b4a.from('ppppp')
  const keypair = Keypair.generate()
  const sig = Keypair.sign(keypair, buf)
  assert.ok(sig)
  const { public, curve } = keypair
  assert.ok(Keypair.verify({ public, curve }, buf, sig))
})

test('sign()/verify a buffer with hmac key', (t) => {
  const buf = b4a.from('ppppp')
  const keypair = Keypair.generate()
  const hmac_key = crypto.randomBytes(32)
  const hmac_key2 = crypto.randomBytes(32)

  const sig = Keypair.sign(keypair, buf, hmac_key)
  assert.ok(sig)
  assert.equal(Keypair.verify(keypair, buf, sig, hmac_key), true)
  assert.equal(Keypair.verify(keypair, buf, sig, hmac_key2), false)
})
