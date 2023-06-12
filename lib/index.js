// @ts-ignore
const sodium = require('sodium-universal')
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
 */

/**
 * @param {any} x
 * @returns {x is string}
 */
function isString(x) {
  return typeof x === 'string'
}

/**
 * @param {any} x
 * @returns {x is Uint8Array}
 */
function isUint8(x) {
  return x instanceof Uint8Array
}

/**
 * @param {Uint8Array} input
 * @param {string | Uint8Array} key
 * @returns {Uint8Array}
 */
function hmac(input, key) {
  if (isString(key)) key = base58.decode(key)
  const output = new Uint8Array(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(output, input, key)
  return output
}

/**
 * Takes a keypair object (where `.public` is allowed to be undefined), a
 * message as a Uint8Array (and an optional hmacKey) and returns a signature of
 * the given message. The signature is string encoded in base58.
 *
 * @param {KeypairPrivateSlice} keypair
 * @param {Uint8Array} msg
 * @param {Uint8Array | string | undefined} hmacKey
 * @returns {string}
 */
function sign(keypair, msg, hmacKey) {
  if (!isUint8(msg)) throw new Error('Signable message should be Uint8Array')
  const curve = getCurve(keypair.curve)

  if (hmacKey) msg = hmac(msg, hmacKey)

  return curve.sign(keypair, msg)
}

/**
 * Takes a keypair object (where `private` is allowed to be undefined), a
 * message Uint8Array and its signature string (and an optional hmacKey), and
 * returns true if the signature is valid for the message, false otherwise.
 *
 * @param {KeypairPublicSlice} keypair
 * @param {Uint8Array} msg
 * @param {string} sig
 * @param {Uint8Array | string | undefined} hmacKey
 * @returns {boolean}
 */
function verify(keypair, msg, sig, hmacKey) {
  if (!isString(sig)) throw new Error('sig should be string')
  if (!isUint8(msg)) throw new Error('Signed message should be Uint8Array')
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
