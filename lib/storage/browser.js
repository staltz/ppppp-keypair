const { generate, getCurve } = require('../curves')
const Storage = require('./common')

/**
 * @typedef {import('../curves').Keypair} Keypair
 *
 * @typedef {(...args: [Error] | [null, Keypair]) => void} Callback
 */

class BrowserStorage extends Storage {
  constructor() {
    super()
  }

  /**
   * @param {string} identifier
   * @returns {Keypair}
   */
  createSync(identifier) {
    const keypair = generate()
    const curve = getCurve(keypair.curve)
    const jsonStr = curve.toJSON(keypair, { indented: false })
    localStorage.setItem(identifier, jsonStr)
    return keypair
  }

  /**
   * @param {string} identifier
   * @returns {Keypair}
   */
  loadSync(identifier) {
    const item = localStorage.getItem(identifier)
    if (!item) {
      throw new Error(`No keypair found at localStorage "${identifier}"`)
    }
    try {
      return JSON.parse(item)
    } catch {
      throw new Error(`Malformed keypair JSON in localStorage ${identifier}`)
    }
  }

  /**
   * @param {string} identifier
   * @param {Callback} cb
   */
  create(identifier, cb) {
    let keypair
    try {
      keypair = this.createSync(identifier)
    } catch (err) {
      cb(/** @type {Error} */ (err))
      return
    }
    cb(null, keypair)
  }

  /**
   * @param {string} identifier
   * @param {Callback} cb
   */
  load(identifier, cb) {
    let keypair
    try {
      keypair = this.loadSync(identifier)
    } catch (err) {
      cb(/** @type {Error} */ (err))
      return
    }
    cb(null, keypair)
  }
}

module.exports = BrowserStorage
