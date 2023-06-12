const ed25519 = require('./ed25519')

const curves = {
  ed25519,
}

/**
 * @typedef {keyof typeof curves} CurveName
 *
 * @typedef {{
 *   curve: CurveName,
 *   public: string,
 *   private: string,
 *   _public?: Uint8Array,
 *   _private?: Uint8Array,
 * }} Keypair
 *
 * @typedef {(Pick<Keypair, 'curve' | 'public'> & {_public: never}) |
 *   (Pick<Keypair, 'curve' | '_public'> & {public: never})
 * } KeypairPublicSlice
 *
 * @typedef {(Pick<Keypair, 'curve' | 'private'> & {_private: never}) |
 *   (Pick<Keypair, 'curve' | '_private'> & {private: never})
 * } KeypairPrivateSlice
 *
 * @typedef {{
 *   generate: (seed?: Uint8Array | string) => Keypair,
 *   toJSON: (keypair: Keypair, opts?: {indented?: boolean}) => string,
 *   sign: (keypair: KeypairPrivateSlice, message: Uint8Array) => Uint8Array,
 *   verify: (keypair: KeypairPublicSlice, message: Uint8Array, sig: Uint8Array) => boolean,
 * }} Curve
 */

/**
 * @param {CurveName} curveName
 */
function getCurve(curveName) {
  if (!curves[curveName]) {
    // prettier-ignore
    throw new Error(`Unknown curve "${curveName}" out of available "${Object.keys(curves).join(',')}"`)
  }
  return curves[curveName]
}

/**
 * This function generates a keypair for the given curve. The seed is optional.
 *
 * @param {CurveName=} curveName
 * @param {(Uint8Array | string)=} seed
 * @returns {Keypair}
 */
function generate(curveName, seed) {
  const curve = getCurve(curveName ?? 'ed25519')
  return curve.generate(seed)
}

module.exports = {
  getCurve,
  generate,
}
