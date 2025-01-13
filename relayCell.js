
var crypto_utils = require('./crypto_utils')

function addZeros(buf, len) {
    return Buffer.concat([buf, Buffer.alloc(len)])
}

class RelayCell {
    constructor(circuit) {
        this.circuit = circuit
    }
    parse(data, beforeDecryptRes) {
        var body = data
        var beforeDecrypt = this.circuit.keyLayers.slice()
        if (beforeDecryptRes == undefined) {
            this.circuit.keyLayers.forEach(function(key) {
                body = crypto_utils.aesDecrypt(key.backwardKey, body, 0)
            })
        } else {
            beforeDecryptRes.forEach(function(key) {
                body = crypto_utils.aesDecrypt(key.backwardKey, body, 0)
            })
        }

        var offset = 0
        var returnData = {}
        returnData["RelayCommand"] = body.readUint8(offset)
        offset += 3
        returnData["StreamID"] = body.readUint16BE(offset)
        offset += 6
        var len = body.readUint16BE(offset)
        offset += 2
        returnData["Body"] = body.slice(offset, offset+len)
        return {
            returnData,
            beforeDecrypt
        }
    }
    buildBody(data) {
        var digest = this.circuit.keyLayers[this.circuit.keyLayers.length-1].fowardDigest
        var totalBody = Buffer.alloc(0)
        var curOffset = 0

        totalBody = addZeros(totalBody, 1)
        totalBody.writeUint8(data["RelayCommand"], curOffset)
        curOffset += 1
        totalBody = addZeros(totalBody, 2)
        totalBody.writeUint16BE(0, curOffset)
        curOffset += 2
        totalBody = addZeros(totalBody, 2)
        totalBody.writeUint16BE(data["StreamID"], curOffset)
        curOffset += 2
        totalBody = Buffer.concat([totalBody, Buffer.alloc(4)])
        curOffset += 4
        totalBody = addZeros(totalBody, 2)
        totalBody.writeUint16BE(data["Body"].length, curOffset)
        curOffset += 2
        totalBody = Buffer.concat([totalBody, data["Body"], Buffer.alloc(509-11-data["Body"].length)])

        digest.update(totalBody)
        var sha1 = digest.copy().digest()
        sha1 = sha1.slice(0, 4)
        
        var otherBody = Buffer.alloc(0)
        var otherOffset = 0

        otherBody = addZeros(otherBody, 1)
        otherBody.writeUint8(data["RelayCommand"], otherOffset)
        otherOffset += 1
        otherBody = addZeros(otherBody, 2)
        otherBody.writeUint16BE(0, otherOffset)
        otherOffset += 2
        otherBody = addZeros(otherBody, 2)
        otherBody.writeUint16BE(data["StreamID"], otherOffset)
        otherOffset += 2
        otherBody = Buffer.concat([otherBody, sha1])
        otherOffset += 4
        otherBody = addZeros(otherBody, 2)
        otherBody.writeUint16BE(data["Body"].length, otherOffset)
        otherOffset += 2
        otherBody = Buffer.concat([otherBody, data["Body"], Buffer.alloc(509-11-data["Body"].length)])

        this.circuit.keyLayers.slice().reverse().forEach(function(key, index) {
            if (index == 1) {
                otherBody = crypto_utils.aesCrypt(key.fowardKey, otherBody, 0)
            } else {
                otherBody = crypto_utils.aesCrypt(key.fowardKey, otherBody, 0)
            }
        })

        return otherBody
    }
}

module.exports = {
    RelayCell
}