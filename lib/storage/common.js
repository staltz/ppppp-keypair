/**
 * @typedef {import('../curves').Keypair} Keypair
 *
 * @typedef {import('../curves').CurveName} CurveName
 *
 * @typedef {(...args: [Error] | [null, Keypair]) => void} Callback
 */

class Storage {
  /**
   * @param {string} identifier
   * @param {Callback} cb
   */
  load(identifier, cb) {
    throw new Error('load() missing an implementation')
  }

  /**
   * @param {string} identifier
   * @param {Callback} cb
   */
  create(identifier, cb) {
    throw new Error('create() missing an implementation')
  }

  /**
   * @param {string} identifier
   * @returns {Keypair}
   */
  loadSync(identifier) {
    throw new Error('loadSync() missing an implementation')
  }

  /**
   * @param {string} identifier
   * @returns {Keypair}
   */
  createSync(identifier) {
    throw new Error('createSync() missing an implementation')
  }

  /**
   * @param {string} identifier
   * @param {Callback} cb
   */
  loadOrCreate(identifier, cb) {
    this.load(identifier, (err, keypair) => {
      if (!err) return cb(null, keypair)
      else this.create(identifier, cb)
    })
  }

  /**
   * @param {string} identifier
   * @returns {Keypair}
   */
  loadOrCreateSync(identifier) {
    try {
      return this.loadSync(identifier)
    } catch {
      return this.createSync(identifier)
    }
  }
}

module.exports = Storage
