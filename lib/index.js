// @ts-ignore
const sodium = require('sodium-universal')
const b4a = require('b4a')
const base58 = require('bs58')
const { getCurve, generate } = require('./curves')
const StorageClass =
  typeof window !== 'undefined'
    ? require('./storage/browser')
    : require('./storage/node')

/**
 * @typedef {import('./curves').Keypair} Keypair
 * @typedef {import('./curves').KeypairPublicSlice} KeypairPublicSlice
 * @typedef {import('./curves').KeypairPrivateSlice} KeypairPrivateSlice
 * @typedef {import('./curves').CurveName} CurveName
 *
 * @typedef {Buffer | Uint8Array} B4A
 */

/**
 * @param {any} x
 * @returns {x is string}
 */
function isString(x) {
  return typeof x === 'string'
}

/**
 * @param {B4A} input
 * @param {string | B4A} key
 * @returns {B4A}
 */
function hmac(input, key) {
  if (isString(key)) key = b4a.from(base58.decode(key))
  const output = b4a.alloc(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(output, input, key)
  return output
}

/**
 * Takes a keypair object (where `.public` is allowed to be undefined), a
 * message as a Buffer (and an optional hmacKey) and returns a signature of
 * the given message. The signature is string encoded in base58.
 *
 * @param {KeypairPrivateSlice} keypair
 * @param {B4A} msg
 * @param {B4A | string | undefined} hmacKey
 * @returns {string}
 */
function sign(keypair, msg, hmacKey) {
  if (!b4a.isBuffer(msg)) throw new Error('Signable message should be Buffer')
  const curve = getCurve(keypair.curve)

  if (hmacKey) msg = hmac(msg, hmacKey)

  return curve.sign(keypair, msg)
}

/**
 * Takes a keypair object (where `private` is allowed to be undefined), a
 * message Buffer and its signature string (and an optional hmacKey), and
 * returns true if the signature is valid for the message, false otherwise.
 *
 * @param {KeypairPublicSlice} keypair
 * @param {B4A} msg
 * @param {string} sig
 * @param {B4A | string | undefined} hmacKey
 * @returns {boolean}
 */
function verify(keypair, msg, sig, hmacKey) {
  if (!isString(sig)) throw new Error('sig should be string')
  if (!b4a.isBuffer(msg)) throw new Error('Signed message should be Buffer')
  const curve = getCurve(keypair.curve)

  if (hmacKey) msg = hmac(msg, hmacKey)

  return curve.verify(keypair, sig, msg)
}

const storage = new StorageClass()

module.exports = {
  generate,
  sign,
  verify,
  create: storage.create.bind(storage),
  load: storage.load.bind(storage),
  createSync: storage.createSync.bind(storage),
  loadSync: storage.loadSync.bind(storage),
  loadOrCreate: storage.loadOrCreate.bind(storage),
  loadOrCreateSync: storage.loadOrCreateSync.bind(storage),
}
