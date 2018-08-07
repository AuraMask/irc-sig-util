const ircUtil = require('icjs-util');
const ircAbi = require('icjs-abi');

const TYPED_MESSAGE_SCHEMA = {
  type: 'object',
  properties: {
    types: {
      type: 'object',
      additionalProperties: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: {type: 'string'},
            type: {type: 'string'},
          },
          required: ['name', 'type'],
        },
      },
    },
    primaryType: {type: 'string'},
    domain: {type: 'object'},
    message: {type: 'object'},
  },
  required: ['types', 'primaryType', 'domain', 'message'],
};

/**
 * A collection of utility functions used for signing typed data
 */
const TypedDataUtils = {
  /**
   * Encodes an object by encoding and concatenating each of its members
   *
   * @param {string} primaryType - Root type
   * @param {Object} data - Object to encode
   * @param {Object} types - Type definitions
   * @returns {string} - Encoded representation of an object
   */
  encodeData(primaryType, data, types) {
    const encodedTypes = ['bytes32'];
    const encodedValues = [this.hashType(primaryType, types)];

    for (const field of types[primaryType]) {
      let value = data[field.name];
      if (value !== undefined) {
        if (field.type === 'string' || field.type === 'bytes') {
          encodedTypes.push('bytes32');
          value = ircUtil.sha3(value);
          encodedValues.push(value);
        } else if (types[field.type] !== undefined) {
          encodedTypes.push('bytes32');
          value = ircUtil.sha3(this.encodeData(field.type, value, types));
          encodedValues.push(value);
        } else if (field.type.lastIndexOf(']') === field.type.length - 1) {
          throw new Error('Arrays currently unimplemented in encodeData');
        } else {
          encodedTypes.push(field.type);
          encodedValues.push(value);
        }
      }
    }

    return ircAbi.rawEncode(encodedTypes, encodedValues);
  },

  /**
   * Encodes the type of an object by encoding a comma delimited list of its members
   *
   * @param {string} primaryType - Root type to encode
   * @param {Object} types - Type definitions
   * @returns {string} - Encoded representation of the type of an object
   */
  encodeType(primaryType, types) {
    let result = '';
    let deps = this.findTypeDependencies(primaryType, types).filter(dep => dep !== primaryType);
    deps = [primaryType].concat(deps.sort());
    for (const type of deps) {
      const children = types[type];
      if (!children) {
        throw new Error(`No type definition specified: ${type}`);
      }
      result += `${type}(${types[type].map(({name, type}) => `${type} ${name}`).join(',')})`;
    }
    return result;
  },

  /**
   * Finds all types within a type defintion object
   *
   * @param {string} primaryType - Root type
   * @param {Object} types - Type definitions
   * @param {Array} results - current set of accumulated types
   * @returns {Array} - Set of all types found in the type definition
   */
  findTypeDependencies(primaryType, types, results = []) {
    if (results.includes(primaryType) || types[primaryType] === undefined) { return results; }
    results.push(primaryType);
    for (const field of types[primaryType]) {
      for (const dep of this.findTypeDependencies(field.type, types, results)) {
        !results.includes(dep) && results.push(dep);
      }
    }
    return results;
  },

  /**
   * Hashes an object
   *
   * @param {string} primaryType - Root type
   * @param {Object} data - Object to hash
   * @param {Object} types - Type definitions
   * @returns {string} - Hash of an object
   */
  hashStruct(primaryType, data, types) {
    return ircUtil.sha3(this.encodeData(primaryType, data, types));
  },

  /**
   * Hashes the type of an object
   *
   * @param {string} primaryType - Root type to hash
   * @param {Object} types - Type definitions
   * @returns {string} - Hash of an object
   */
  hashType(primaryType, types) {
    return ircUtil.sha3(this.encodeType(primaryType, types));
  },

  /**
   * Removes properties from a message object that are not defined per EIP-712
   *
   * @param {Object} data - typed message object
   * @returns {Object} - typed message object with only allowed fields
   */
  sanitizeData(data) {
    const sanitizedData = {};
    for (const key in TYPED_MESSAGE_SCHEMA.properties) {
      data[key] && (sanitizedData[key] = data[key]);
    }
    return sanitizedData;
  },

  /**
   * Signs a typed message as per EIP-712 and returns its sha3 hash
   *
   * @param {Object} typedData - Types message data to sign
   * @returns {string} - sha3 hash of the resulting signed message
   */
  sign(typedData) {
    sanitizedData = this.sanitizeData(typedData);
    const parts = [Buffer.from('1901', 'hex')];
    parts.push(this.hashStruct('EIP712Domain', sanitizedData.domain, sanitizedData.types));
    parts.push(this.hashStruct(sanitizedData.primaryType, sanitizedData.message, sanitizedData.types));
    return ircUtil.sha3(Buffer.concat(parts));
  },
};

module.exports = {
  TYPED_MESSAGE_SCHEMA,
  TypedDataUtils,

  concatSig: function(v, r, s) {
    const rSig = ircUtil.fromSigned(r);
    const sSig = ircUtil.fromSigned(s);
    const vSig = ircUtil.bufferToInt(v);
    const rStr = padWithZeroes(ircUtil.toUnsigned(rSig).toString('hex'), 64);
    const sStr = padWithZeroes(ircUtil.toUnsigned(sSig).toString('hex'), 64);
    const vStr = ircUtil.stripHexPrefix(ircUtil.intToHex(vSig));
    return ircUtil.addHexPrefix(rStr.concat(sStr, vStr)).toString('hex');
  },

  normalize: function(input) {
    if (!input) return;

    if (typeof input === 'number') {
      const buffer = ircUtil.toBuffer(input);
      input = ircUtil.bufferToHex(buffer);
    }

    if (typeof input !== 'string') {
      var msg = 'irc-sig-util.normalize() requires hex string or integer input.';
      msg += ' received ' + (typeof input) + ': ' + input;
      throw new Error(msg);
    }

    return ircUtil.addHexPrefix(input.toLowerCase());
  },

  personalSign: function(privateKey, msgParams) {
    var message = ircUtil.toBuffer(msgParams.data);
    var msgHash = ircUtil.hashPersonalMessage(message);
    var sig = ircUtil.ecsign(msgHash, privateKey);
    var serialized = ircUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s));
    return serialized;
  },

  recoverPersonalSignature: function(msgParams) {
    const publicKey = getPublicKeyFor(msgParams);
    const sender = ircUtil.publicToAddress(publicKey);
    const senderHex = ircUtil.bufferToHex(sender);
    return senderHex;
  },

  extractPublicKey: function(msgParams) {
    const publicKey = getPublicKeyFor(msgParams);
    return '0x' + publicKey.toString('hex');
  },

  typedSignatureHash: function(typedData) {
    const hashBuffer = typedSignatureHash(typedData);
    return ircUtil.bufferToHex(hashBuffer);
  },

  signTypedDataLegacy: function(privateKey, msgParams) {
    const msgHash = typedSignatureHash(msgParams.data);
    const sig = ircUtil.ecsign(msgHash, privateKey);
    return ircUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s));
  },

  recoverTypedSignatureLegacy: function(msgParams) {
    const msgHash = typedSignatureHash(msgParams.data);
    const publicKey = recoverPublicKey(msgHash, msgParams.sig);
    const sender = ircUtil.publicToAddress(publicKey);
    return ircUtil.bufferToHex(sender);
  },

  signTypedData: function(privateKey, msgParams) {
    const message = TypedDataUtils.sign(msgParams.data);
    const sig = ircUtil.ecsign(message, privateKey);
    return ircUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s));
  },

  recoverTypedSignature: function(msgParams) {
    const message = TypedDataUtils.sign(msgParams.data);
    const publicKey = recoverPublicKey(message, msgParams.sig);
    const sender = ircUtil.publicToAddress(publicKey);
    return ircUtil.bufferToHex(sender);
  },

};

/**
 * @param typedData - Array of data along with types, as per EIP712.
 * @returns Buffer
 */
function typedSignatureHash(typedData) {
  const error = new Error('Expect argument to be non-empty array');
  if (typeof typedData !== 'object' || !typedData.length) throw error;

  const data = typedData.map(function(e) {
    return e.type === 'bytes' ? ircUtil.toBuffer(e.value) : e.value;
  });
  const types = typedData.map(function(e) { return e.type; });
  const schema = typedData.map(function(e) {
    if (!e.name) throw error;
    return e.type + ' ' + e.name;
  });

  return ircAbi.soliditySHA3(
      ['bytes32', 'bytes32'],
      [
        ircAbi.soliditySHA3(new Array(typedData.length).fill('string'), schema),
        ircAbi.soliditySHA3(types, data),
      ],
  );
}

function recoverPublicKey(hash, sig) {
  const signature = ircUtil.toBuffer(sig);
  const sigParams = ircUtil.fromRpcSig(signature);
  return ircUtil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s);
}

function getPublicKeyFor(msgParams) {
  const message = ircUtil.toBuffer(msgParams.data);
  const msgHash = ircUtil.hashPersonalMessage(message);
  return recoverPublicKey(msgHash, msgParams.sig);
}

function padWithZeroes(number, length) {
  var myString = '' + number;
  while (myString.length < length) {
    myString = '0' + myString;
  }
  return myString;
}
