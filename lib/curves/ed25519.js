// @ts-ignore
const sodium = require('sodium-universal')
const base58 = require('bs58')

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
   * @param {(string | Buffer)=} seed
   * @returns {Keypair}
   */
  generate(seed) {
    let seedBuf
    if (seed) {
      if (Buffer.isBuffer(seed)) {
        // prettier-ignore
        if (seed.length !== SEEDBYTES) throw new Error(`seed must be ${SEEDBYTES} bytes`)
        seedBuf = seed
      } else if (typeof seed === 'string') {
        seedBuf = Buffer.alloc(SEEDBYTES)
        const slice = seed.substring(0, SEEDBYTES)
        Buffer.from(slice, 'utf-8').copy(seedBuf)
      }
    }

    const publicKeyBuf = Buffer.alloc(PUBLICKEYBYTES)
    const secretKeyBuf = Buffer.alloc(SECRETKEYBYTES)
    if (seedBuf) {
      sodium.crypto_sign_seed_keypair(publicKeyBuf, secretKeyBuf, seedBuf)
    } else {
      sodium.crypto_sign_keypair(publicKeyBuf, secretKeyBuf)
    }

    return {
      curve: 'ed25519',
      public: base58.encode(publicKeyBuf),
      private: base58.encode(secretKeyBuf),
      _public: publicKeyBuf,
      _private: secretKeyBuf,
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
   * @param {Buffer} message
   * @returns {string}
   */
  sign(keypair, message) {
    if (!keypair._private && !keypair.private) {
      throw new Error(`invalid ed25519 keypair with missing private key`)
    }
    keypair._private ??= Buffer.from(base58.decode(keypair.private))
    const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, message, keypair._private)
    return base58.encode(sig)
  },

  /**
   * @param {KeypairPublicSlice} keypair
   * @param {string} sig
   * @param {Buffer} message
   * @returns {boolean}
   */
  verify(keypair, sig, message) {
    if (!keypair._public && !keypair.public) {
      throw new Error(`invalid ed25519 keypair with missing public key`)
    }
    keypair._public ??= Buffer.from(base58.decode(keypair.public))
    const sigBuf = Buffer.from(base58.decode(sig))
    return sodium.crypto_sign_verify_detached(sigBuf, message, keypair._public)
  },
}

module.exports = ed25519
