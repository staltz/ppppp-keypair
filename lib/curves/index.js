const ed25519 = require('./ed25519')

const curves = {
  ed25519,
}

/**
 * @typedef {keyof typeof curves} CurveName
 *
 * @typedef {Buffer | Uint8Array} B4A
 *
 * @typedef {{
 *   curve: CurveName,
 *   public: string,
 *   private: string,
 *   _public?: B4A,
 *   _private?: B4A,
 * }} Keypair
 *
 * @typedef {Pick<Keypair, 'curve' | 'public' | '_public'>} KeypairPublicSlice
 *
 * @typedef {Pick<Keypair, 'curve' | 'private' | '_private'>} KeypairPrivateSlice
 *
 * @typedef {{
 *   generate: (seed?: B4A | string) => Keypair,
 *   toJSON: (keypair: Keypair, opts?: {indented?: boolean}) => string,
 *   sign: (keypair: KeypairPrivateSlice, message: B4A) => string,
 *   verify: (keypair: KeypairPublicSlice, sig: string, message: B4A) => boolean,
 * }} Curve
 */

/**
 * @param {CurveName} curveName
 * @returns {Curve}
 */
function getCurve(curveName) {
  if (!curves[curveName]) {
    // prettier-ignore
    throw new Error(`Unknown curve "${curveName}" out of available "${Object.keys(curves).join(',')}"`)
  }
  return /** @type {Curve} */ (curves[curveName])
}

/**
 * This function generates a keypair for the given curve. The seed is optional.
 *
 * @param {CurveName=} curveName
 * @param {(B4A | string)=} seed
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
