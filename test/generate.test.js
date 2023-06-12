const test = require('node:test')
const assert = require('node:assert')
const Keypair = require('../lib/index')

test('generate() default', (t) => {
  const keypair = Keypair.generate()
  assert.equal(keypair.curve, 'ed25519')
  assert.equal(typeof keypair.public, 'string')
  assert.equal(typeof keypair.private, 'string')
  assert.equal(keypair._public instanceof Uint8Array, true)
  assert.equal(keypair._private instanceof Uint8Array, true)
  assert.deepEqual(Object.keys(keypair), [
    'curve',
    'public',
    'private',
    '_public',
    '_private',
  ])
})

test('generate() with ed25519 curve', (t) => {
  const keypair = Keypair.generate('ed25519')
  assert.equal(keypair.curve, 'ed25519')
  assert.equal(typeof keypair.public, 'string')
  assert.equal(typeof keypair.private, 'string')
})

test('generate() with unknown curve', (t) => {
  assert.throws(() => {
    Keypair.generate('foobar')
  }, /Unknown curve "foobar"/)
})

test('generate() with seed', (t) => {
  const keypair = Keypair.generate('ed25519', 'alice')
  assert.equal(keypair.public, '4mjQ5aJu378cEu6TksRG3uXAiKFiwGjYQtWAjfVjDAJW')
})