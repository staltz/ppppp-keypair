const fs = require('node:fs')
const path = require('node:path')
const { mkdirp } = require('mkdirp')
const { generate, getCurve } = require('../curves')
const Storage = require('./common')

/**
 * @typedef {import('../curves').Keypair} Keypair
 *
 * @typedef {(...args: [Error] | [null, Keypair]) => void} Callback
 */

class NodeStorage extends Storage {
  constructor() {
    super()
  }

  /** @type {BufferEncoding} */
  #fileEncoding = 'ascii'

  /** @type {fs.WriteFileOptions} */
  #fileWriteOpts = { mode: 0x100, flag: 'wx', encoding: this.#fileEncoding }

  /**
   * @param {Keypair} keypair
   * @returns {string}
   */
  #toFileContents(keypair) {
    const curve = getCurve(keypair.curve)
    const jsonStr = curve.toJSON(keypair, { indented: true })

    return `# WARNING: Never show this to anyone.
# WARNING: Never edit it or use it on multiple devices at once.
#
# This is your SECRET, it gives you magical powers. With your secret you can
# sign your messages so that your friends can verify that the messages came
# from you. If anyone learns your secret, they can use it to impersonate you.
#
# If you use this secret on more than one device you will create a fork and
# your friends will stop replicating your content.
#
${jsonStr}
#
# The only part of this file that's safe to share is your public name:
#
#   ${keypair.public}`
  }

  /**
   * @param {string} contents
   * @return {Keypair}
   */
  #fromFileContents(contents) {
    const json = contents
      .replace(/\s*#[^\n]*/g, '')
      .split('\n')
      .filter((x) => !!x)
      .join('')

    try {
      const keypair = JSON.parse(json)
      return keypair
    } catch {
      throw new Error(`Malformed keypair JSON in file contents`)
    }
  }

  /**
   * @param {string} filename
   * @returns {Keypair}
   */
  createSync(filename) {
    const keypair = generate()
    const fileContents = this.#toFileContents(keypair)
    mkdirp.sync(path.dirname(filename))
    fs.writeFileSync(filename, fileContents, this.#fileWriteOpts)
    return keypair
  }

  /**
   * @param {string} filename
   * @returns {Keypair}
   */
  loadSync(filename) {
    const fileContents = fs.readFileSync(filename, this.#fileEncoding)
    const keypair = this.#fromFileContents(fileContents)
    return keypair
  }

  /**
   * @param {string} filename
   * @param {Callback} cb
   */
  create(filename, cb) {
    const keypair = generate()
    const fileContents = this.#toFileContents(keypair)
    mkdirp(path.dirname(filename)).then(() => {
      fs.writeFile(filename, fileContents, this.#fileWriteOpts, (err) => {
        if (err) cb(err)
        else cb(null, keypair)
      })
    }, cb)
  }

  /**
   * @param {string} filename
   * @param {Callback} cb
   */
  load(filename, cb) {
    fs.readFile(filename, this.#fileEncoding, (err, fileContents) => {
      if (err) return cb(err)

      /** @type {Keypair} */
      let keypair
      try {
        keypair = this.#fromFileContents(fileContents)
      } catch (err) {
        cb(/** @type {Error} */ (err))
        return
      }
      cb(null, keypair)
    })
  }
}

module.exports = NodeStorage
