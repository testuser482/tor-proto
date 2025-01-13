var { x25519  } = require('@noble/curves/ed25519')
var { SHA3 } = require('sha3')
var { ed25519 } = require('@noble/curves/ed25519')
var crypto = require('crypto')
var aesjs = require('aes-js');
var x509 = require('@peculiar/x509')
var webcrypto = require('@peculiar/webcrypto')

const webCrypt = new webcrypto.Crypto();
x509.cryptoProvider.set(webCrypt);

const alg = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 1024,
};

function aesCrypt(key, data, counterDat) {
    var bufWrite = key.update(data)
    return bufWrite
}


function aesDecrypt(key, data) {
    var bufWrite = key.update(data)
    return bufWrite
}

async function newCertificate(publicKey, privateKey) {
    var publicKeyUse = await webCrypt.subtle.importKey("jwk", publicKey.export({
        format: 'jwk'
    }), alg, true, ['sign', 'verify', 'decrypt', ])
    var privateKeyUse = await webCrypt.subtle.importKey("jwk", privateKey.export({
        format: 'jwk'
    }), alg, true, ['sign', 'verify', 'decrypt', ])

    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        name: "CN=www.bur4xpd7dw44.com",
        signingAlgorithm: alg,
        notBefore: getTimeOneYearBeforeNow(),
        notAfter: getTimeOneYearFromNow(),    
        keys: {
            publicKey: publicKeyUse,
            privateKey: privateKeyUse
        },
        extensions: [
            new x509.BasicConstraintsExtension(true, 2, true),
            new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
            await x509.SubjectKeyIdentifierExtension.create(publicKeyUse),
        ]
    });

    return cert.rawData
      
}

function encapsulate(num) {
    var header = Buffer.alloc(4)
    var len = Buffer.alloc(4)
    len.writeUInt32BE(num.length, 0)
    header = Buffer.concat([header, len])
    return Buffer.concat([header, Buffer.from(num)])
}

function sha256(data) {
    var hash = crypto.createHash('sha256')
    hash.update(data)
    return hash.digest()
}

function sha1(data) {
    var hash = crypto.createHash('sha1')
    hash.update(data)
    return hash.digest()
}

function sha1Incomplete(data) {
    var hash = crypto.createHash('sha1')
    hash.update(data)
    return hash
}

function sha3_256(data) {
    const hash = new SHA3(256)
    hash.update(data)
    return hash.digest()
}

function h(s, tweak) {
    return sha3_256(Buffer.concat([encapsulate(tweak), s]))
}

function h_key_seed(s) {
    return h(s, t_key_seed)
}

function h_verify(s) {
    return h(s, t_verify)
}

function h_auth(s) {
    return h(s, t_auth)
}

function mac(s, key, tweak) {
    return sha3_256(Buffer.concat([encapsulate(tweak), encapsulate(key), s]))
}

function kdfParse(m_expand, key_seed) {
    var lenRequired = (20 * 2) + (16 * 2) + 20
    var K = Buffer.alloc(0)
    var index = 0
    while (K.length < lenRequired) {
        var hMacData = Buffer.concat([K, Buffer.from(m_expand), Buffer.from([index])])
        var hMac = crypto.createHmac('sha256', key_seed)
            .update(hMacData)
            .digest()
        K = Buffer.concat([K, hMac])
        index += 1
    }
    return {
        fowardDigest: K.slice(0, 20),
        backwardDigest: K.slice(20, 40),
        fowardKey: K.slice(40, 56),
        backwardKey: K.slice(56, 72),
        nonce: K.slice(72, 92)
    }
}

var PROTOID = "ntor3-curve25519-sha3_256-1"
var t_msgkdf = PROTOID + ":kdf_phase1"
var t_msgmac = PROTOID + ":msg_mac"
var t_key_seed = PROTOID + ":key_seed"
var t_verify = PROTOID + ":verify"
var t_final = PROTOID + ":kdf_final"
var t_auth = PROTOID + ":auth_final"

function mac_phase1(s, key) {
    return mac(s, key, t_msgmac)
}
function kdf(s, tweak) {
    var dataHash = Buffer.concat([encapsulate(tweak), s])
    var hash = crypto.createHash('shake256', {
        outputLength: 1024
    })
    hash.update(dataHash)
    return new ByteSeq(hash.digest())
}

function kdf_phase1(s) {
    return kdf(s, t_msgkdf)
}

function kdf_final(s) {
    return kdf(s, t_final)
}

DIGEST_LEN = 32
ENC_KEY_LEN = 32
PUB_KEY_LEN = 32
SEC_KEY_LEN = 32
IDENTITY_LEN = 32
MAC_KEY_LEN = 32

function enc(data, key) {
    var aesCtr = new aesjs.ModeOfOperation.ctr(new Uint8Array(key), new aesjs.Counter(0));
    var encryptedBytes = aesCtr.encrypt(new Uint8Array(data));    

    return Buffer.from(encryptedBytes)
}

function method1(buf) {
    let bits = 8n
    if (ArrayBuffer.isView(buf)) {
      bits = BigInt(buf.BYTES_PER_ELEMENT * 8)
    } else {
      buf = new Uint8Array(buf)
    }
  
    let ret = 0n
    for (const i of buf.values()) {
      const bi = BigInt(i)
      ret = (ret << bits) + bi
    }
    return ret
}

class ByteSeq {
    constructor(data) {
        this.data = data
    }

    take(n) {
        var result = this.data.slice(0, n)
        this.data = this.data.slice(n)
        return result
    }

    exhausted() {
        return this.data.length == 0
    }

    remaining(self) {
        return this.data.length
    }
}

function generateKeys() {
    var _connectionKey = x25519.utils.randomPrivateKey()
    var _connectionPublicKey = x25519.getPublicKey(_connectionKey)
    return {
        keys: {
            connection: {
                public: _connectionPublicKey,
                private: _connectionKey,
            }
        },
    }
}

function timeToHours(date) {
    var timeStampHours = 1000 * 60 * 60
    var date = Math.floor(date.getTime() / timeStampHours)
    return date
}

function getTimeOneYearFromNow() {
    var timeStampHours = 1000 * 60 * 60 * 24 * 365
    return new Date(Date.now() + timeStampHours)
}

function getTimeOneYearBeforeNow() {
    var timeStampHours = 1000 * 60 * 60 * 24 * 365
    return new Date(Date.now() - timeStampHours)
}

var KEY_LEN = 16
var HASH_LEN = 20

function fromKDF(createVal, createdVal) {
    var keyMaterial = Buffer.concat([createVal, createdVal])

    var deriviedKey = Buffer.alloc(0)
    var counter = 0

    while (deriviedKey.length < (KEY_LEN * 2 + HASH_LEN * 3)) {

        var hash = crypto.createHash('sha1')
        hash.update(Buffer.concat([keyMaterial, Buffer.from([counter])]))

        deriviedKey = Buffer.concat([deriviedKey, hash.digest()])

        counter += 1
    }

    var offset = 0
    var keyHash = deriviedKey.slice(offset, offset + HASH_LEN)
    offset += HASH_LEN
    var fowardDigest = deriviedKey.slice(offset, offset + HASH_LEN)
    offset += HASH_LEN
    var backwardDigest = deriviedKey.slice(offset, offset + HASH_LEN)
    offset += HASH_LEN
    var fowardKey = deriviedKey.slice(offset, offset + KEY_LEN)
    offset += KEY_LEN
    var backwardKey = deriviedKey.slice(offset, offset + KEY_LEN)
    offset += KEY_LEN

    return {
        keyHash,
        fowardDigest,
        backwardDigest,
        fowardKey,
        backwardKey
    }
}

module.exports = {
    generateKeys,
    newCertificate,
    sha256,
    sha1,
    timeToHours,
    enc,
    aesCrypt,
    aesDecrypt,
    sha1Incomplete,
    getTimeOneYearFromNow,
    encapsulate,
    kdf_phase1,
    h_key_seed,
    h_verify,
    ByteSeq,
    h_auth,
    kdf_final,
    mac_phase1,
    kdfParse,
    fromKDF
}

