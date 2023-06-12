// @ts-ignore
const sodium = require('sodium-universal')
const base58 = require('bs58')
const _TextEncoder =
  typeof window !== 'undefined'
    ? window.TextEncoder
    : require('node:util').TextEncoder

/**
 * @typedef {import('.').Keypair} Keypair
 *
 * @typedef {import('.').KeypairPublicSlice} KeypairPublicSlice
 *
 * @typedef {import('.').KeypairPrivateSlice} KeypairPrivateSlice
 */

const SEEDBYTES = sodium.crypto_sign_SEEDBYTES
const PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES
const SECRETKEYBYTES = sodium.crypto_sign_SECRETKEYBYTES

const ed25519 = {
  /**
   * @param {(string | Uint8Array)=} seed
   * @returns {Keypair}
   */
  generate(seed) {
    let seedBytes
    if (seed) {
      if (seed instanceof Uint8Array) {
        // prettier-ignore
        if (seed.length !== SEEDBYTES) throw new Error(`seed must be ${SEEDBYTES} bytes`)
        seedBytes = seed
      } else if (typeof seed === 'string') {
        seedBytes = new Uint8Array(SEEDBYTES)
        new _TextEncoder().encodeInto(seed, seedBytes)
      }
    }

    const publicKeyBytes = new Uint8Array(PUBLICKEYBYTES)
    const secretKeyBytes = new Uint8Array(SECRETKEYBYTES)
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
   * @param {Uint8Array} message
   * @returns {string}
   */
  sign(keypair, message) {
    if (!keypair._private && !keypair.private) {
      throw new Error(`invalid ed25519 keypair with missing private key`)
    }
    keypair._private ??= base58.decode(keypair.private)
    const sig = new Uint8Array(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, message, keypair._private)
    return base58.encode(sig)
  },

  /**
   * @param {KeypairPublicSlice} keypair
   * @param {string} sig
   * @param {Uint8Array} message
   * @returns {boolean}
   */
  verify(keypair, sig, message) {
    if (!keypair._public && !keypair.public) {
      throw new Error(`invalid ed25519 keypair with missing public key`)
    }
    keypair._public ??= base58.decode(keypair.public)
    const sigBytes = new Uint8Array(base58.decode(sig))
    return sodium.crypto_sign_verify_detached(
      sigBytes,
      message,
      keypair._public
    )
  },
}

module.exports = ed25519
