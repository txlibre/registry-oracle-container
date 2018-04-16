const BN = require('bn.js')
const Decimal = require('decimal.js')
const EdDSA = require('elliptic').eddsa
const ec = new EdDSA('ed25519')
const blake2b = require('blake2b')
const sha256 = require('sha256')
const promisify = require('es6-promisify')
const cloudscraper = require('cloudscraper')
const request = promisify(cloudscraper.request)
const exec = require('child_process').exec
const cmd = promisify(exec)

const URL = 'https://check.tezos.com/'
const ATTEMPTS = 5

const PK_LEN = 64
const ADDR_LEN = 40
const SIGNATURE_LEN = 128

const MAGICPREFIX = '06a19f'
const CODE_STRING_BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

const SUCCESS = '0'
const FAIL_WITH_SIGN_OK = '1'
const FAIL = '2'

const BTC_DECIMAL = new Decimal(10 ** 8)
const ETH_DECIMAL = new Decimal(10 ** 18)
const TZL_DECIMAL = new Decimal(10 ** 18)

const TOLERANCE_SATOSHIS = new BN('10000') // 0.00010000 btc
const TOLERANCE_WEI = new BN('1000000000000000') // 0.0010000 eth

const EPSILON = new Decimal(100)
const MIN_TEZZIES_FOR_SATOSHI = (new Decimal(5000)).sub(EPSILON).div(BTC_DECIMAL)
const MAX_TEZZIES_FOR_SATOSHI = (new Decimal(6000)).add(EPSILON).div(BTC_DECIMAL)

const MIN_BTC_FOR_ETH = new Decimal(0.06288792)
const MIN_TEZZIES_FOR_WEI = MIN_BTC_FOR_ETH.mul(BTC_DECIMAL).mul(MIN_TEZZIES_FOR_SATOSHI).div(ETH_DECIMAL)
const MAX_BTC_FOR_ETH = new Decimal(0.14436016)
const MAX_TEZZIES_FOR_WEI = MAX_BTC_FOR_ETH.mul(BTC_DECIMAL).mul(MAX_TEZZIES_FOR_SATOSHI).div(ETH_DECIMAL)

const DECLARATION = 'I hereby cryptographically prove to be a contributor of Tezos Stiftung (CHE-290.597.458), a Swiss Foundation based in Gubelstrasse 11, 6300 Zug, Switzerland. I recognize and welcome the existence multiple implementations of Tezos. I ask and expect Tezos Stiftung to foster competition among them by funding and supporting their development, marketing and growth. Funds allotted to various Tezos implementations shall always be directly proportional to their market capitalization at the time of each distribution of funds. Distribution of funds to multiple existing Tezos implementations shall begin no later than January 1st 2019 and consistently continue throughout time. Following priorities autonomously set by each community, Tezos Stiftung shall distribute funds in the most appropriate, effective and transparent way.'

/**
 * remove_0x_prefix
 * Remove the 0x prefix
 *
 * @param {String} str
 * @return {String}
 */

function remove_0x_prefix (str) {
  if (str.startsWith('0x')) {
    return str.slice(2)
  }

  return str
}

/**
 * canonize_and_check
 * Remove 0x prefix and check length of the input.
 *
 * @param {String} input.
 * @param {Number} len
 * @return {String
 */

function canonize_and_check (input, len) {
  let canonized = remove_0x_prefix(input)
  let has_correct_length = canonized.length === len
  return has_correct_length ? canonized : ''
}

/**
 * bin_dbl_sha256
 *
 * @param data {Buffer}
 * @return {Buffer}
 */

function bin_dbl_sha256 (data) {
  return Buffer.from(sha256.x2(data), 'hex')
}

/**
 * decode (from base 256)
 *
 * @param data {Buffer}
 * @return {BN}
 */

function decode (data) {
  let len = data.length
  let result = new BN()
  let base = new BN(256)
  let counter = 0

  while (counter < len) {
    result.imul(base)
    result.iadd(new BN(data[counter]))
    counter += 1
  }
  return result
}

/**
 * encode (to base 58)
 *
 * @param val {BN}
 * @return {String}
 */

function encode (val) {
  let result = ''
  let base = new BN(58)
  let m

  while (val > 0) {
    m = val.umod(base).toString(10)
    result = CODE_STRING_BASE58[m] + result
    val = val.div(base)
  }

  return result
}

/**
 * to_base58
 *
 * @param digest {Buffer}
 * @return {String}
 */

function to_base58 (digest) {
  return encode(decode(digest))
}

/**
 * to_b58check
 *
 * @param digest {Buffer}
 * @return {String}
 */

function to_b58check (digest) {
  let magic_buf = Buffer.from(MAGICPREFIX, 'hex')
  let magic_buf_len = magic_buf.length
  let checksum_len = 4
  let buf_len = magic_buf_len + digest.length + checksum_len
  let buf = Buffer.allocUnsafe(buf_len)
  let acc = 0
  let checksum_buf
  let checksum

  acc += magic_buf.copy(buf, 0)
  acc += digest.copy(buf, acc)
  checksum_buf = buf.slice(0, acc)
  checksum = bin_dbl_sha256(checksum_buf).slice(0, checksum_len)
  acc += checksum.copy(buf, acc)

  return to_base58(buf)
}

/**
 * hash
 * Compute 64 byte long Blake2b hash of a message.
 *
 * @param {String} msg // no 0x-prefixed
 * @param {String} enc ['hex'|'utf8'] // no 0x-prefixed
 * @return {Buffer}
 */

function hash (msg, enc) {
  let buf = Buffer.from(msg, enc)
  let hash = blake2b(64).update(buf).digest('hex')

  return Buffer.from(hash, 'hex')
}

/**
 * verify
 * Tezos signature verification on eth address.
 *
 * @param {String} signature // no 0x-prefixed
 * @param {String} msg // no 0x-prefixed
 * @param {String} tzl_pk // no 0x-prefixed
 * @return {Boolean}
 */

function verify (signature, msg, tzl_pk, enc) {
  // create key pair from public
  let key = ec.keyFromPublic(tzl_pk, 'hex')

  // generate message hash
  let msgHash = Buffer.from(hash(msg, enc))

  // verify and return
  return key.verify(msgHash, signature)
}
exports.verify = verify

/**
 * compute_tzl_pkh
 * Compute Tezos address from public key.
 *
 * @param {String} tzl_pk // no 0x-prefixed
 * @return {String}
 */

function compute_tzl_pkh (tzl_pk) {
  const tzl_pk_buf = Buffer.from(tzl_pk, 'hex')
  const tzl_pkh_buf = Buffer.from(blake2b(20).update(tzl_pk_buf).digest())
  return to_b58check(tzl_pkh_buf)
}

/**
 * sleep
 * Sleep process for msec
 *
 * @param {Number} msec
 */

function sleep (msec) {
  return new Promise(function (resolve, reject) {
    setTimeout(function () {
      resolve()
    }, msec)
  })
}

/**
 * fetch_json
 * Fetch JSON data from https://check.tezos.com/<tzl_pkh>.json
 * (exploiting anti-CloudFlare librabry trying 5 times).
 *
 * @param {String} tzl_pkh
 * @return {Object}
 */

async function fetch_json (tzl_pkh) {
  let url = `${URL}${tzl_pkh}.json`
  let opts = {
    method: 'GET',
    url: url,
    json: true
  }
  let wrong_tzl_pk = false
  let i = 0
  let status
  let json
  let res

  while (i++ < ATTEMPTS && !json && !wrong_tzl_pk) {
    res = await request(opts)
    status = res.statusCode
    wrong_tzl_pk = status === 404

    if (status === 200) {
      json = res && res.body
    }

    if (!json && !wrong_tzl_pk) {
      sleep(5000)
    }
  }

  return json
}
exports.fetch_json = fetch_json

/**
 * well_formed
 *
 */

function well_formed (json, tzl_addr) {
  let ok = true

  // check btc contributions
  ok = ok && json.utxos !== undefined
  ok = ok && json.utxos.every(
    i =>
      i.txId !== undefined &&
      i.vout !== undefined &&
      i.satoshis !== undefined &&
      i.tezzies !== undefined
  )

  // check eth contributions
  ok = ok && json.ethDeposits !== undefined
  ok = ok && json.ethDeposits.every(
    i =>
      i.transactionHash !== undefined &&
      i.wei !== undefined &&
      i.tezzies !== undefined
  )

  ok = ok && (tzl_addr !== undefined ? tzl_addr === json.tz_pkh : true)

  return ok
}
exports.well_formed = well_formed

/**
 * parse_db_btc
 *
 */

function parse_db_btc (lines) {
  let entries = lines.split('\n').filter(x => x.trim() !== '')
  let output = {}
  entries.forEach(function (entry) {
    let fields = entry.split(' ')
    let txId = fields.shift()
    let vouts = output[txId] = {}
    for (let i = 0; i < fields.length; i += 2) {
      vouts[fields[i]] = fields[i + 1]
    }
  })
  return output
}

/**
 * parse_db_eth
 *
 */

function parse_db_eth (lines) {
  let entries = lines.split('\n').filter(x => x.trim() !== '')
  let output = {}
  entries.forEach(function (entry) {
    let fields = entry.split(' ')
    output[fields[0]] = fields[1]
  })

  return output
}

/**
 * are_equal_bn
 *
 */

function are_equal_bn (a, b, tolerance) {
  let a_bn = new BN(a)
  let b_bn = new BN(b)

  return a_bn.sub(b_bn).abs().lte(tolerance)
}

/**
 * are_equal_dec
 *
 */

function are_equal_dec (a, b, tolerance) {
  let a_dec = new Decimal(a)
  let b_dec = new Decimal(b)

  return a_dec.sub(b_dec).abs().lte(tolerance)
}

/**
 * is_in_interval_dec
 *
 * @param {Decimal} value
 * @param {Decimal} min
 * @param {Decimal} max
 * @return {Boolean}
 *
 */

function is_in_interval_dec (value, min, max) {
  let out = false
  if (value.gte(min) && value.lte(max)) {
    out = true
  }
  return out
}

/**
 * check_btc_contrib
 *
 */

async function check_btc_contrib (b) {
  // success if no btc contribution has been made
  if (b.length === 0) {
    return true
  }

  let query = b.map(el => el.txId).join('\\|')
  let result = await cmd(`bzcat db/btc | grep '${query}'`)
  let parsed_result = parse_db_btc(result)

  let is_valid = b.every(function (el) {
    // check existance of contribution
    let test = are_equal_bn(
      parsed_result[el.txId][el.vout], el.satoshis.toString(), TOLERANCE_SATOSHIS
    )
    // check the correctness of assigned tezzies amount
    let tezzies_for_satoshi = new Decimal(el.tezzies).div(new Decimal(el.satoshis))
    test = test && is_in_interval_dec(tezzies_for_satoshi, MIN_TEZZIES_FOR_SATOSHI, MAX_TEZZIES_FOR_SATOSHI)
    return test
  })

  return is_valid
}

/**
 * check_eth_contrib
 *
 */

async function check_eth_contrib (e) {
  // success if no eth contribution has been made
  if (e.length === 0) {
    return true
  }

  let query = e.map(el => el.transactionHash).join('\\|')
  let result = await cmd(`bzcat db/eth | grep '${query}'`)
  let parsed_result = parse_db_eth(result)
  let is_valid = e.every(function (el) {
    // check existance of contribution
    let test = are_equal_bn(
      parsed_result[el.transactionHash], el.wei.toString(), TOLERANCE_WEI
    )
    // check the correctness of assigned tezzies amount
    let tezzies_for_wei = new Decimal(el.tezzies).div(new Decimal(el.wei))
    test = test && is_in_interval_dec(tezzies_for_wei, MIN_TEZZIES_FOR_WEI, MAX_TEZZIES_FOR_WEI)
    return test
  })

  return is_valid
}

/**
 * every
 * Async every function.
 *
 * @param {Array} array
 * @param {Function} iterator
 * @return {Boolean}
 */

async function every (array, iterator) {
  let out = true

  for (let el of array) {
    out = await iterator(el)
    if (!out) { break }
  }

  return out
}

/**
 * check_contribution_amount
 * Verify contribution in static DB
 * (lookup via external bzcat and grep).
 *
 * @param {Object} json
 * @return {Boolean}
 */

async function check_contribution_amount (json) {
  let btc_contributions = json.utxos
  let eth_contributions = json.ethDeposits
  let valid_btc_contrib = await check_btc_contrib(btc_contributions)
  let valid_eth_contrib = await check_eth_contrib(eth_contributions)

  return valid_btc_contrib && valid_eth_contrib
}
exports.check_contribution_amount = check_contribution_amount

/**
 * count_tezzies
 * Count total amount of tezzies
 *
 * @param {Object} json
 * @return {Decimal}
 */

function count_tezzies (json) {
  let zero = new Decimal(0)

  let reducer = function (a, b) {
    let b_dec = new Decimal(b.tezzies)
    return a.add(b_dec)
  }

  // count tezzies from btc contributions
  let tezzies_btc = json.utxos.reduce(reducer, zero)

  // count tezzies from eth contributions
  let tezzies_eth = json.ethDeposits.reduce(reducer, zero)

  // sum contributions
  let tezzies = tezzies_btc.add(tezzies_eth)

  return tezzies
}

/**
 * get_tzl_amount
 * Return the tezzies amount.
 * It is not the amount directly reported by the JSON
 * but it is computed by summing up all the individual contribution.
 *
 * @param {Object} json
 * @return {Decimal}
 */

function get_tzl_amount (json) {
  let tezzies = count_tezzies(json)
  let tezzies_dec = tezzies.mul(TZL_DECIMAL)
  return tezzies_dec
}
exports.get_tzl_amount = get_tzl_amount

/** MAIN **/
async  function main () {
  let status_code = FAIL

  try {
    let argv = process.argv
    let tzl_pk = canonize_and_check(argv[2], PK_LEN)
    let eth_addr = canonize_and_check(argv[3], ADDR_LEN)
    let addr_signature = canonize_and_check(argv[4], SIGNATURE_LEN)
    let declaration_signature = canonize_and_check(argv[5], SIGNATURE_LEN)
    let has_input = !!tzl_pk && !!eth_addr && !!addr_signature && !! declaration_signature

    if (!has_input) {
      console.log(status_code) // FAIL
      return
    }

    let valid_addr_signature = verify(addr_signature, eth_addr, tzl_pk, 'hex')

    if (!valid_addr_signature) {
      console.log(status_code) // FAIL
      return
    }

    let valid_declaration_signature = verify(declaration_signature, DECLARATION, tzl_pk, 'utf8')

    if (!valid_declaration_signature) {
      console.log(status_code) // FAIL
      return
    }

    status_code = FAIL_WITH_SIGN_OK

    let tzl_pkh = compute_tzl_pkh(tzl_pk)
    let json = await fetch_json(tzl_pkh)

    if (!json) {
      throw new Error('Can\'t fetch contribution json.')
    }

    if (!well_formed(json, tzl_pkh)) {
      throw new Error('Fetched json is not well formed.')
    }

    let correct_contribution = await check_contribution_amount(json)

    if (!correct_contribution) {
      throw new Error('Invalid contribution.')
    }

    let tzl_amount = get_tzl_amount(json)

    if (tzl_amount.lte(0)) {
      throw new Error('Invalid Tezos amount.')
    }

    // set SUCCESS status code
    status_code = SUCCESS

    let tzl_amount_dec = tzl_amount.toFixed(0)
    let output = `${status_code} ${tzl_pkh} ${tzl_amount_dec}`
    console.log(output)

  } catch (e) {
    console.log(status_code)
  }
}

if (typeof require !== undefined && require.main === module) {
  main().then().catch(err => console.log(e))
}
