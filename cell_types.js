

var crypto = require('crypto')
var os = require('os')
var utils = require('./crypto_utils')


class CreateFast {
    constructor() {

    }
    build(keyMaterial) {
        return Buffer.from(keyMaterial)
    }
}

class CreatedFast {
    constructor() {

    }
    parse(buf) {
        var curOffset = 0
        var keyMaterial = buf.slice(curOffset, curOffset+20)
        curOffset += 20

        var DerivativeKeyData = buf.slice(curOffset, curOffset+20)
        curOffset + 20

        return {
            keyMaterial: keyMaterial,
            DerivativeKeyData: DerivativeKeyData
        }
    }
}

class AuthenticationCell {
    constructor() {

    }

    buildPre(data) {
        var authBuf = Buffer.concat([Buffer.from("AUTH0003"), 
            data["CID"], 
            data["SID"],
            data["CID_ED"],
            data["SID_ED"],
            data["SLOG"],
            data["CLOG"],
            data["SCERT"],
            data["TLSSECRETS"],
            data["RAND"],
        ])

        return authBuf
    }

    finalBuild(authBuf) {
        var buf = Buffer.alloc(0)
        var offsetMain = 0
        buf = addZeros(buf, 2)
        buf.writeUint16BE(3, offsetMain)
        offsetMain += 2
        buf = addZeros(buf, 2)
        buf.writeUint16BE(authBuf.length, offsetMain)
        offsetMain += 2
        buf = Buffer.concat([buf, authBuf])
        return buf
    }
}

class NetInfo {
    constructor() {

    }

    writeResponse(netInfoPrevious) {
        var localNetInfo = netInfoPrevious["OTHERADDR"].Data
        var otherNetInfo = undefined
        var addressType = 0x04
        netInfoPrevious["MYADDR"].forEach(function(address) {
            if (address.Type == 0x04) {
                otherNetInfo = address.Data
            }
        })
        var response = {
            "Timestamp": 0,
            "OTHERADDR": {
                "Type": addressType,
                "Data": otherNetInfo
            },
            "MYADDR": [
                {
                    "Type": addressType,
                    "Data": localNetInfo
                }
            ]
        }
        return this.build(response)
    }

    build(mainData) {
        var mainBuf = Buffer.alloc(0)
        var curOffset = 0
        mainBuf = addZeros(mainBuf, 4)
        mainBuf.writeUint32BE(mainData["Timestamp"], curOffset)
        curOffset += 4
        mainBuf = addZeros(mainBuf, 1)
        mainBuf.writeUint8(mainData["OTHERADDR"]["Type"], curOffset)
        curOffset += 1
        mainBuf = addZeros(mainBuf, 1)
        mainBuf.writeUint8(mainData["OTHERADDR"]["Data"].length, curOffset)
        curOffset += 1
        mainBuf = Buffer.concat([mainBuf, mainData["OTHERADDR"]["Data"]])
        curOffset += mainData["OTHERADDR"]["Data"].length
        mainBuf = addZeros(mainBuf, 1)
        mainBuf.writeUint8(mainData["MYADDR"].length, curOffset)
        curOffset += 1
        mainData["MYADDR"].forEach(function(address) {
            mainBuf = addZeros(mainBuf, 1)
            mainBuf.writeUint8(address.Type, curOffset)
            curOffset += 1
            mainBuf = addZeros(mainBuf, 1)
            mainBuf.writeUint8(address.Data.length, curOffset)
            curOffset += 1
            mainBuf = Buffer.concat([mainBuf, address.Data])
            curOffset += address.Data.length    
        })
        return mainBuf
    }

    parse(buf) {
        var curOffset = 0
        var dataRespond = {}
        dataRespond["Timestamp"] = buf.readUint32BE(curOffset)
        curOffset += 4
        dataRespond["OTHERADDR"] = {}
        dataRespond["OTHERADDR"]["Type"] = buf.readUint8(curOffset)
        curOffset += 1
        dataRespond["OTHERADDR"]["Len"] = buf.readUint8(curOffset)
        curOffset += 1
        dataRespond["OTHERADDR"]["Data"] = buf.slice(curOffset, curOffset + dataRespond["OTHERADDR"]["Len"])
        curOffset += dataRespond["OTHERADDR"]["Len"]
        dataRespond["MYADDR"] = []
        var NMYADDR = buf.readUint8(curOffset)
        curOffset += 1
        for (var i = 0; i < NMYADDR; i++) {
            var dataSet = {}
            dataSet["Type"] = buf.readUint8(curOffset)
            curOffset += 1
            dataSet["Len"] = buf.readUint8(curOffset)
            curOffset += 1
            dataSet["Data"] = buf.slice(curOffset, curOffset + dataSet["Len"])
            curOffset += dataSet["Len"]
            dataRespond["MYADDR"].push(dataSet)
        }
        return dataRespond
    }
}

class Cell {
    constructor(isTrue) {
        this._use4Len = isTrue
    }

    getReciviedBytes(buf) {
        var totalRecivedBytes = Buffer.alloc(0)
        var _use4Len = false
        var offset = 0
        while (true) {
            var curcuitId = 0
            if (_use4Len == true) {
                if (buf.readUint8(offset + 4) == 8) {
                    return totalRecivedBytes
                    break
                }
                curcuitId = buf.readUint32BE(offset)
                totalRecivedBytes = addZeros(totalRecivedBytes, 4)
                totalRecivedBytes.writeUint32BE(curcuitId, offset)
                offset += 4
            } else {
                if (buf.readUint8(offset + 2) == 8) {
                    return totalRecivedBytes
                    break
                }
                curcuitId = buf.readUint16BE(offset)
                totalRecivedBytes = addZeros(totalRecivedBytes, 2)
                totalRecivedBytes.writeUint16BE(curcuitId, offset)
                offset += 2
                _use4Len = true
            }
            var command = buf.readUint8(offset)
            totalRecivedBytes = addZeros(totalRecivedBytes, 1)
            totalRecivedBytes.writeUint8(command, offset)
            offset += 1
            if (command > 128 || command == 7) {
                var payloadLen = buf.readUint16BE(offset)
                totalRecivedBytes = addZeros(totalRecivedBytes, 2)
                totalRecivedBytes.writeUint16BE(payloadLen, offset)    
                offset += 2
                var payload = buf.slice(offset, offset+payloadLen)
                totalRecivedBytes = Buffer.concat([totalRecivedBytes, payload])
                offset += payloadLen
            } else {
                var payload = buf.slice(offset, offset+509)
                totalRecivedBytes = Buffer.concat([totalRecivedBytes, payload])
                offset += 509
            }
            if ((buf.length-offset) <= 0) {
                break
            }
        }
        return totalRecivedBytes
    }

    decodeCell(buf) {
        var totalParsedCircuitData = {}
        var offset = 0
        while (true) {
            var curcuitId = 0
            if (this._use4Len == true) {
                curcuitId = buf.readUint32BE(offset)
                offset += 4
            } else {
                curcuitId = buf.readUint16BE(offset)
                offset += 2
                this._use4Len = true
            }
            var command = buf.readUint8(offset)
            offset += 1
            if (command > 128 || command == 7) {
                var payloadLen = buf.readUint16BE(offset)
                offset += 2
                var payload = buf.slice(offset, offset+payloadLen)
                totalParsedCircuitData[command] = this.parseCell(payload, command)
                offset += payloadLen
            } else {
                var payload = buf.slice(offset, offset+509)
                totalParsedCircuitData[command] = this.parseCell(payload, command)
                offset += 509
            }
            if ((buf.length-offset) <= 0) {
                break
            }
        }
        return totalParsedCircuitData
    }

    buildCell(type, data, id, longVer) {
        if (type > 128 || type == 7) {
            var buf = undefined
            if (longVer == true) {
                buf = Buffer.alloc(7)
                buf.writeUint32BE(id, 0)
                buf.writeUint8(type, 4)
                buf.writeUint16BE(data.length, 5)   
            } else {
                buf = Buffer.alloc(5)
                buf.writeUint16BE(id, 0)
                buf.writeUint8(type, 2)
                buf.writeUint16BE(data.length, 3)    
            }
            return Buffer.concat([buf, data])
        } else {
            var buf = undefined
            if (longVer == true) {
                buf = Buffer.alloc(5)
                buf.writeUint32BE(id, 0)
                buf.writeUint8(type, 4)
            } else {
                buf = Buffer.alloc(3)
                buf.writeUint16BE(id, 0)
                buf.writeUint8(type, 2)
            }
            if (data.length < 509) {
                data = addZeros(data, 509-data.length)
            }
            return Buffer.concat([buf, data])
        }
    }
    
    parseCell(payload, command) {
        var totalParsedData = {}
        switch(command) {
            case 129:
                var certs = new CERTS()
                return certs.parse(payload)
            case 130:
                var auth = new AUTH_CHALLENGE()
                return auth.parse(payload)
            case 8:
                var netInfo = new NetInfo()
                return netInfo.parse(payload)
            case 7:
                var versionInfo = new VersionCell()
                return versionInfo.parse(payload)
            case 6:
                var createdInfo = new CreatedFast()
                return createdInfo.parse(payload)
        }
        return totalParsedData
    }
}


class AUTH_CHALLENGE {
    constructor() {
    }

    parse(buf) {
        var offset = 0
        var challenge = buf.slice(offset, offset+32)
        offset += 32
        var N_Methods = buf.readUint16BE(offset)
        offset += 2
        var methods = buf.slice(offset, offset+(2*N_Methods))
        offset += (2*N_Methods)
        return {
            challenge: challenge,
            methods: methods
        }
    }
}

class VersionCell {
    constructor(versions) {
        this.versions = versions
    }
    build() {
        var buf = Buffer.alloc(2*this.versions.length)
        this.versions.forEach(function(val, index) {
            buf.writeUint16BE(val, (index*2))
        })
        return buf
    }
    parse(bufWork) {
        var amount = bufWork.length/2
        var versions = []
        for (var i = 0; i < amount; i++) {
            versions.push(bufWork.readUint16BE(i*2))
        }
        return versions
    }
}

function addZeros(buf, len) {
    return Buffer.concat([buf, Buffer.alloc(len)])
}

class CERTS {
    constructor() {

    }

    buildPre(options) {
        var buf = Buffer.alloc(0)
        var curOffset = 0
        buf = addZeros(buf, 1)
        buf.writeUint8(1, curOffset)
        curOffset += 1
        buf = addZeros(buf, 1)
        buf.writeUint8(options["CERT_TYPE"], curOffset)
        curOffset += 1
        buf = addZeros(buf, 4)
        buf.writeUint32BE(options["EXPIRATION_DATE"], curOffset)
        curOffset += 4
        buf = addZeros(buf, 1)
        buf.writeUint8(options["CERT_KEY_TYPE"], curOffset)
        curOffset += 1
        buf = Buffer.concat([buf, options["CERTIFIED_KEY"]])
        curOffset += 32
        buf = addZeros(buf, 1)
        buf.writeUint8(options["N_EXTENSIONS"].length, curOffset)
        curOffset += 1
        options["N_EXTENSIONS"].forEach(function(extenstion) {
            buf = addZeros(buf, 2)
            buf.writeUint16BE(extenstion["ExtData"].length, curOffset)
            curOffset += 2
            buf = addZeros(buf, 1)
            buf.writeUint8(extenstion["ExtType"], curOffset)
            curOffset += 1
            buf = addZeros(buf, 1)
            buf.writeUint8(extenstion["ExtFlags"], curOffset)
            curOffset += 1     
            buf = Buffer.concat([buf, extenstion["ExtData"]]) 
            curOffset += extenstion["ExtData"].length
        })
        return buf
    }

    builtType2Pre(options) {
        var buf = options["KEY"]
        var curOffset = 32
        buf = addZeros(buf, 4)
        buf.writeUint32BE(options["EXPIRATION_DATE"], curOffset)
        curOffset += 4
        return buf
    }

    builtType2(options) {
        var buf = options["KEY"]
        var curOffset = 32
        buf = addZeros(buf, 4)
        buf.writeUint32BE(options["EXPIRATION_DATE"], curOffset)
        curOffset += 4
        buf = addZeros(buf, 1)
        buf.writeUint8(options["SIGLEN"], curOffset)
        curOffset += 1
        buf = Buffer.concat([buf, options["SIGNATURE"]])
        return buf;
    }

    buildCertArray(certs) {
        var buf = Buffer.alloc(0)
        var offset = 0
        buf = addZeros(buf, 1)
        buf.writeUint8(certs.length, offset)
        offset += 1
        certs.forEach(function(cert) {
            buf = addZeros(buf, 1)
            buf.writeUint8(cert.type, offset)
            offset += 1
            buf = addZeros(buf, 2)
            buf.writeUint16BE(cert.payload.length, offset)
            offset += 2
            buf = Buffer.concat([buf, cert.payload])
            offset += cert.payload.length
        })
        return buf
    }

    parse(buf) {
        var offset = 0
        var certificateNum = buf.readUint8(offset)
        var totalCerts = []
        offset += 1
        while (true) {
            var certType = buf.readUint8(offset)
            offset += 1
            var certLen = buf.readUint16BE(offset)
            offset += 2
            var certPayload = buf.slice(offset, offset+certLen)
            offset += certLen
            var certData = {}
            switch (certType) {
                case 4:
                    var offsetOther = 0
                    certData["VERSION"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    certData["CERT_TYPE"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    certData["EXPIRATION_DATE"] = certPayload.readUint32BE(offsetOther)
                    offsetOther += 4
                    certData["CERT_KEY_TYPE"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    certData["CERTIFIED_KEY"] = certPayload.slice(offsetOther, offsetOther+32)
                    offsetOther += 32
                    certData["N_EXTENSIONS_COUNT"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    var N_EXTENSIONS = []
                    for (var i = 0; i < certData["N_EXTENSIONS_COUNT"]; i++) {
                        var curData = {}
                        curData["ExtLen"] = certPayload.readUint16BE(offsetOther)
                        offsetOther += 2
                        curData["ExtType"] = certPayload.readUint8(offsetOther)
                        offsetOther += 1
                        curData["ExtFlags"] = certPayload.readUint8(offsetOther)
                        offsetOther += 1
                        curData["ExtData"] = certPayload.slice(offsetOther, offsetOther+curData["ExtLen"])
                        offsetOther += curData["ExtLen"]
                        N_EXTENSIONS.push(curData)
                    }
                    certData["N_EXTENSIONS"] = N_EXTENSIONS
                    certData["Signature"] = certPayload.slice(offsetOther, offsetOther+64)
                    totalCerts.push(certData)
                    break 
                case 5:
                    var offsetOther = 0
                    certData["VERSION"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    certData["CERT_TYPE"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    certData["EXPIRATION_DATE"] = certPayload.readUint32BE(offsetOther)
                    offsetOther += 4
                    certData["CERT_KEY_TYPE"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    certData["CERTIFIED_KEY"] = certPayload.slice(offsetOther, offsetOther+32)
                    offsetOther += 32
                    certData["N_EXTENSIONS_COUNT"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    var N_EXTENSIONS = []
                    for (var i = 0; i < certData["N_EXTENSIONS_COUNT"]; i++) {
                        var curData = {}
                        curData["ExtLen"] = certPayload.readUint16BE(offsetOther)
                        offsetOther += 2
                        curData["ExtType"] = certPayload.readUint8(offsetOther)
                        offsetOther += 1
                        curData["ExtFlags"] = certPayload.readUint8(offsetOther)
                        offsetOther += 1
                        curData["ExtData"] = certPayload.slice(offsetOther, offsetOther+curData["ExtLen"])
                        offsetOther += curData["ExtLen"]
                        N_EXTENSIONS.push(curData)
                    }
                    certData["N_EXTENSIONS"] = N_EXTENSIONS
                    certData["Signature"] = certPayload.slice(offsetOther, offsetOther+64)
                    totalCerts.push(certData)
                    break
                case 7:
                    var offsetOther = 0
                    var certData = {}
                    certData["CERT_TYPE"] = 7
                    certData["KEY"] = certPayload.slice(offsetOther, offsetOther+32)
                    offsetOther += 32
                    certData["EXPIRATION_DATE"] = certPayload.readUint32BE(offsetOther)
                    offsetOther += 4
                    certData["SIGLEN"] = certPayload.readUint8(offsetOther)
                    offsetOther += 1
                    certData["SIGNATURE"] = certPayload.slice(offsetOther, offsetOther+certData["SIGLEN"])
                    offsetOther += certData["SIGLEN"]
                    totalCerts.push(certData)
                    break
                case 2:
                    var cert = new crypto.X509Certificate('-----BEGIN CERTIFICATE-----\n' + certPayload.toString('base64') + '\n-----END CERTIFICATE-----')
                    var publicKey = cert.publicKey.export({
                        format: 'der',
                        type: 'pkcs1'
                    })
                    totalCerts.push({
                        "CERT_TYPE": 2,
                        "KEY": publicKey
                    })

            }
            if ((buf.length-offset) <= 0) {
                break
            }
        }
        return totalCerts
    }
}

module.exports = {
    CERTS,
    VersionCell,
    AUTH_CHALLENGE,
    AuthenticationCell,
    NetInfo,
    CreateFast,
    Cell,
    addZeros
}