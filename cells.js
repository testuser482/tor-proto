var tls = require('tls')
var types = require('./cell_types')
var { Circuit } = require('./circuit')
var { ed25519 } = require('@noble/curves/ed25519')
var crypto_utils = require('./crypto_utils')
var remoteCertificate = undefined
var crypto = require('crypto')

var main = new Circuit()
var socket = tls.connect({
    host: '178.218.144.18',
    port: '443',
    rejectUnauthorized: false,
})

function newCertType7(expirationData, main) {
    var Certs = new types.CERTS()
    var jsonBuild = {
        "KEY": Buffer.from(main.storage.keys.relayId.public),
        "EXPIRATION_DATE": expirationData
    }

    var pre = Certs.builtType2Pre(jsonBuild)

    pre = Buffer.concat([Buffer.from("Tor TLS RSA/Ed25519 cross-certificate"), pre])

    const sign = crypto.sign("SHA256", pre, {
        padding: crypto.constants.RSA_PKCS1_PADDING,
        key: main.storage.keys.rsa.private
    }); 

    jsonBuild["SIGLEN"] = sign.length
    jsonBuild["SIGNATURE"] = sign

    jsonBuild = Certs.builtType2(jsonBuild)

    return jsonBuild
}

var cellHandler = new types.Cell()

async function genCertType2(main) {
    return Buffer.from(await crypto_utils.newCertificate(main.storage.keys.rsa.public, main.storage.keys.rsa.private))
}

function genCertType4(expirationData, main) {
    var Certs = new types.CERTS()

    var jsonBuild = {
        "CERT_TYPE": 4,
        "EXPIRATION_DATE": expirationData,
        "CERT_KEY_TYPE": 1,
        "CERTIFIED_KEY": Buffer.from(main.storage.keys.signing.public),
        "N_EXTENSIONS": [
            {
                "ExtType": 4,
                "ExtFlags": 0,
                "ExtData": Buffer.from(main.storage.keys.relayId.public)
            }
        ]
    }

    jsonBuild = Certs.buildPre(jsonBuild)

    var signed = Buffer.from(ed25519.sign(jsonBuild, main.storage.keys.relayId.private))

    jsonBuild = Buffer.concat([jsonBuild, Buffer.from(signed)])

    return jsonBuild
}

function getCertType6(expirationData, main) {
    var Certs = new types.CERTS()

    var jsonBuild = {
        "CERT_TYPE": 6,
        "EXPIRATION_DATE": expirationData,
        "CERT_KEY_TYPE": 1,
        "CERTIFIED_KEY": Buffer.from(main.storage.keys.link.public),
        "N_EXTENSIONS": []
    }

    console.log('Cert data 6:')
    console.log(jsonBuild)

    // write code for certificates


    jsonBuild = Certs.buildPre(jsonBuild)

    var signed = ed25519.sign(jsonBuild, main.storage.keys.signing.private)

    jsonBuild = Buffer.concat([jsonBuild, Buffer.from(signed)])

    return jsonBuild
}

var responseDataGot = undefined
socket.on('data', async function(res) {
    console.log(res)
    if (responseDataGot != undefined) {
        responseDataGot(res)
    }
    console.log('got response work!')
})


function writeAndWaitForResponse(data) {
    return new Promise((resolve,reject) => {
        responseDataGot = function(data) {
            resolve(data)
        }
        socket.write(data, function() {
            
        })
    })
}

socket.on('ready', async function() {
    console.log('ready')
})