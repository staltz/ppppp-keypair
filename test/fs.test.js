const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const Keypair = require('../lib/index')

const keyPath = path.join(os.tmpdir(), `ppppp-keypair-${Date.now()}`)

test('loadSync()', (t) => {
  const keypair = Keypair.generate('ed25519')
  fs.writeFileSync(keyPath, JSON.stringify(keypair))

  const keypair2 = Keypair.loadSync(keyPath)
  assert.ok(keypair2.public)
  assert.equal(keypair2.public, keypair.public)
  fs.unlinkSync(keyPath)
})

test('load()', (t, done) => {
  const keypair = Keypair.generate('ed25519')
  fs.writeFileSync(keyPath, JSON.stringify(keypair))

  Keypair.load(keyPath, (err, keypair2) => {
    assert.ifError(err)
    assert.ok(keypair2.public)
    assert.equal(keypair2.public, keypair.public)
    fs.unlinkSync(keyPath)
    done()
  })
})

test('create() then load()', (t, done) => {
  Keypair.create(keyPath, (err, k1) => {
    assert.ifError(err)
    Keypair.load(keyPath, (err, k2) => {
      assert.ifError(err)
      assert.equal(k1.private, k2.private)
      assert.equal(k1.public, k2.public)
      fs.unlinkSync(keyPath)
      done()
    })
  })
})

test('createSync() then loadSync()', (t) => {
  const k1 = Keypair.createSync(keyPath)
  const k2 = Keypair.loadSync(keyPath)
  assert.equal(k1.private, k2.private)
  assert.equal(k1.public, k2.public)
  fs.unlinkSync(keyPath)
})

test('create()/createSync() avoid overwriting existing keys', (t, done) => {
  fs.writeFileSync(keyPath, 'this file intentionally left blank', 'utf8')
  assert.throws(() => {
    Keypair.createSync(keyPath)
  })
  Keypair.create(keyPath, (err) => {
    assert.ok(err)
    done()
  })
})

test('loadOrCreate() can load', (t, done) => {
  const keyPath = path.join(os.tmpdir(), `ssb-keys-1-${Date.now()}`)
  const keypair = Keypair.generate('ed25519')
  fs.writeFileSync(keyPath, JSON.stringify(keypair))

  Keypair.loadOrCreate(keyPath, (err, keypair2) => {
    assert.ifError(err)
    assert.ok(keypair2.public)
    assert.equal(keypair2.public, keypair.public)
    fs.unlinkSync(keyPath)
    done()
  })
})

test('loadOrCreate() can create', (t, done) => {
  const keyPath = path.join(os.tmpdir(), `ssb-keys-2-${Date.now()}`)
  assert.equal(fs.existsSync(keyPath), false)

  Keypair.loadOrCreate(keyPath, (err, keypair) => {
    assert.ifError(err)
    assert.ok(keypair.public.length > 20, 'keys.public is a long string')
    assert.ok(keypair.private.length > 20, 'keys.private is a long string')
    assert.equal(typeof keypair.curve, 'string', 'keys.curve is a string')
    fs.unlinkSync(keyPath)
    done()
  })
})

test('loadOrCreateSync() can load', (t) => {
  const keyPath = path.join(os.tmpdir(), `ssb-keys-3-${Date.now()}`)
  const keypair = Keypair.generate('ed25519')
  fs.writeFileSync(keyPath, JSON.stringify(keypair))

  const keypair2 = Keypair.loadOrCreateSync(keyPath)
  assert.ok(keypair2.public)
  assert.equal(keypair2.public, keypair.public)
  fs.unlinkSync(keyPath)
})

test('loadOrCreateSync() can create', (t) => {
  const keyPath = path.join(os.tmpdir(), `ssb-keys-4-${Date.now()}`)
  assert.equal(fs.existsSync(keyPath), false)

  const keypair = Keypair.loadOrCreateSync(keyPath)
  assert.ok(keypair.public.length > 20, 'keys.public is a long string')
  assert.ok(keypair.private.length > 20, 'keys.private is a long string')
  assert.ok(keypair.curve, 'keys.curve is a string')
  fs.unlinkSync(keyPath)
})

test('loadOrCreate() doesnt create dir for fully-specified path', (t, done) => {
  const keyPath = path.join(os.tmpdir(), `ssb-keys-5-${Date.now()}`)
  assert.equal(fs.existsSync(keyPath), false)

  Keypair.loadOrCreate(keyPath, (err) => {
    assert.ifError(err)
    assert.ok(fs.lstatSync(keyPath).isFile())

    Keypair.loadOrCreate(keyPath, (err, keypair) => {
      assert.ifError(err)
      assert.ok(keypair.public.length > 20)
      fs.unlinkSync(keyPath)
      done()
    })
  })
})
