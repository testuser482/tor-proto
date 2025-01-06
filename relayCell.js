
var cellUtils = require('./cell_types')
var crypto_utils = require('./crypto_utils')

class RelayCell {
    constructor() {

    }
    buildBody(data, key, digest) {
        var totalBody = Buffer.alloc(0)
        var curOffset = 0

        totalBody = cellUtils.addZeros(totalBody, 1)
        totalBody.writeUint8(data["RelayCommand"], curOffset)
        curOffset += 1
        totalBody = cellUtils.addZeros(totalBody, 2)
        totalBody.writeUint16BE(0, curOffset)
        curOffset += 2
        totalBody = cellUtils.addZeros(totalBody, 2)
        totalBody.writeUint16BE(data["StreamID"], curOffset)
        curOffset += 2
        totalBody = Buffer.concat([totalBody, Buffer.alloc(4)])
        curOffset += 4
        totalBody = cellUtils.addZeros(totalBody, 2)
        totalBody.writeUint16BE(data["Body"].length, curOffset)
        curOffset += 2
        totalBody = Buffer.concat([totalBody, data["Body"], Buffer.alloc(509-11-data["Body"].length)])

        digest.update(totalBody)
        var sha1 = digest.digest()
        sha1 = sha1.slice(0, 4)
        
        var otherBody = Buffer.alloc(0)
        var otherOffset = 0

        otherBody = cellUtils.addZeros(otherBody, 1)
        otherBody.writeUint8(data["RelayCommand"], otherOffset)
        otherOffset += 1
        otherBody = cellUtils.addZeros(otherBody, 2)
        otherBody.writeUint16BE(0, otherOffset)
        otherOffset += 2
        otherBody = cellUtils.addZeros(otherBody, 2)
        otherBody.writeUint16BE(data["StreamID"], otherOffset)
        otherOffset += 2
        otherBody = Buffer.concat([otherBody, sha1])
        otherOffset += 4
        otherBody = cellUtils.addZeros(otherBody, 2)
        otherBody.writeUint16BE(data["Body"].length, otherOffset)
        otherOffset += 2
        otherBody = Buffer.concat([otherBody, data["Body"], Buffer.alloc(509-11-data["Body"].length)])

        return crypto_utils.aesCrypt(key, otherBody)
    }
}

module.exports = {
    RelayCell
}