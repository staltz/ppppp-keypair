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
 * @returns {x is Buffer}
 */
function isBuffer(x) {
  return Buffer.isBuffer(x)
}

/**
 * @param {Buffer} input
 * @param {string | Buffer} key
 * @returns {Buffer}
 */
function hmac(input, key) {
  if (isString(key)) key = Buffer.from(base58.decode(key))
  const output = Buffer.alloc(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(output, input, key)
  return output
}

/**
 * Takes a keypair object (where `.public` is allowed to be undefined), a
 * message as a buffer (and an optional hmacKey) and returns a signature of the
 * given message. The signature is string encoded in base58.
 *
 * @param {KeypairPrivateSlice} keypair
 * @param {Buffer} msg
 * @param {Buffer | string | undefined} hmacKey
 * @returns {string}
 */
function sign(keypair, msg, hmacKey) {
  if (!isBuffer(msg)) throw new Error('Signable message should be buffer')
  const curve = getCurve(keypair.curve)

  if (hmacKey) msg = hmac(msg, hmacKey)

  return curve.sign(keypair, msg)
}

/**
 * Takes a keypair object (where `private` is allowed to be undefined), a
 * message buffer and its signature string (and an optional hmacKey), and
 * returns true if the signature is valid for the message, false otherwise.
 *
 * @param {KeypairPublicSlice} keypair
 * @param {Buffer} msg
 * @param {string} sig
 * @param {Buffer | string | undefined} hmacKey
 * @returns {boolean}
 */
function verify(keypair, msg, sig, hmacKey) {
  if (!isString(sig)) throw new Error('sig should be string')
  if (!isBuffer(msg)) throw new Error('Signed message should be buffer')
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
