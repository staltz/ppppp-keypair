// @ts-ignore
const sodium = require('sodium-universal')
const b4a = require('b4a')
const base58 = require('bs58')

/**
 * @typedef {import('.').Keypair} Keypair
 * @typedef {import('.').Curve} Curve
 * @typedef {import('.').KeypairPublicSlice} KeypairPublicSlice
 * @typedef {import('.').KeypairPrivateSlice} KeypairPrivateSlice
 *
 * @typedef {Buffer | Uint8Array} B4A
 */

const SEEDBYTES = sodium.crypto_sign_SEEDBYTES
const PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES
const SECRETKEYBYTES = sodium.crypto_sign_SECRETKEYBYTES

/** @type {Curve} */
const ed25519 = {
  /**
   * @param {(string | B4A)=} seed
   * @returns {Keypair}
   */
  generate(seed) {
    let seedBytes
    if (seed) {
      if (b4a.isBuffer(seed)) {
        // prettier-ignore
        if (seed.length !== SEEDBYTES) throw new Error(`seed must be ${SEEDBYTES} bytes`)
        seedBytes = seed
      } else if (typeof seed === 'string') {
        seedBytes = b4a.alloc(SEEDBYTES)
        b4a.copy(b4a.from(seed.substring(0, 32), 'utf-8'), seedBytes)
      }
    }

    const publicKeyBytes = b4a.alloc(PUBLICKEYBYTES)
    const secretKeyBytes = b4a.alloc(SECRETKEYBYTES)
    if (seedBytes) {
      sodium.crypto_sign_seed_keypair(publicKeyBytes, secretKeyBytes, seedBytes)
    } else {
      sodium.crypto_sign_keypair(publicKeyBytes, secretKeyBytes)
    }

    return {
      curve: 'ed25519',
      public: base58.encode(publicKeyBytes),
      private: base58.encode(secretKeyBytes),
      _public: publicKeyBytes,
      _private: secretKeyBytes,
    }
  },

  /**
   * @param {Keypair} keypair
   * @param {{indented?: boolean}=} opts
   */
  toJSON(keypair, opts) {
    const stringifiable = {
      curve: keypair.curve,
      public: keypair.public,
      private: keypair.private,
    }
    if (opts?.indented) {
      return JSON.stringify(stringifiable, null, 2)
    } else {
      return JSON.stringify(stringifiable)
    }
  },

  /**
   * @param {KeypairPrivateSlice} keypair
   * @param {B4A} message
   * @returns {string}
   */
  sign(keypair, message) {
    if (!keypair._private && !keypair.private) {
      throw new Error(`invalid ed25519 keypair with missing private key`)
    }
    keypair._private ??= b4a.from(base58.decode(keypair.private))
    const sig = b4a.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, message, keypair._private)
    return base58.encode(sig)
  },

  /**
   * @param {KeypairPublicSlice} keypair
   * @param {string} sig
   * @param {B4A} message
   * @returns {boolean}
   */
  verify(keypair, sig, message) {
    if (!keypair._public && !keypair.public) {
      throw new Error(`invalid ed25519 keypair with missing public key`)
    }
    keypair._public ??= b4a.from(base58.decode(keypair.public))
    const sigBytes = b4a.from(base58.decode(sig))
    return sodium.crypto_sign_verify_detached(
      sigBytes,
      message,
      keypair._public
    )
  },
}

module.exports = ed25519
