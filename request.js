var { RelayCell } = require('./relayCell')
var types = require('./cell_types')
const HTTPTag = require('http-tag')

async function connect(circuit, ip, port) {
    var data = Buffer.concat([Buffer.from(ip), Buffer.from(":"), Buffer.from(port.toString()), Buffer.from([0])])
    console.log(data.toString())
    data = Buffer.concat([data, Buffer.alloc(1)])
    var resData = new RelayCell(circuit).buildBody({
        RelayCommand: 1,
        StreamID: 2,
        Body: data
    })
    var response = new types.Cell(circuit, true).decodeCell(
        await circuit.writeAndWaitForResponse(
            new types.Cell().buildCell(3, resData, circuit.circuitId, true)
        )
    )
    console.log(new Uint8Array(response['3'].Body))
    var resData2 = new RelayCell(circuit).buildBody({
        RelayCommand: 2,
        StreamID: 2,
        Body: Buffer.from(HTTPTag`GET /us-en HTTP/1.1
Host: www.ibm.com
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: keep-alive
`)
    })
    var beforeDecrypt = undefined
    circuit.socket.on('data', function(data) {
        console.log(data)
        callback = circuit.cellHandler.decodeCell(data)
        if (callback['3'] != undefined) {
            if (Array.isArray(callback['3'])) {
                callback['3'].forEach(function(dat) {
                    console.log(dat.returnData.Body.toString())        
                })
            } else {
                beforeDecrypt = callback['3'].beforeDecrypt
                console.log(callback['3'].returnData.Body.toString())        
            }
        } else {
            if (callback['0'] != undefined) {

            } else {
                callback = new RelayCell(circuit).parse(data, beforeDecrypt)
                console.log(callback.returnData.Body.toString())
            }
        }
    })
    circuit.socket.write(circuit.cellHandler.buildCell(3, resData2, circuit.circuitId, true))
    

}

async function resolveDNS(circuit, name) {
    var name = Buffer.concat([Buffer.from(name), Buffer.from([0])])
    var resData = new RelayCell(circuit).buildBody({
        RelayCommand: 11,
        StreamID: 1,
        Body: name
    })
    var response = new types.Cell(circuit, true).decodeCell(
        await circuit.writeAndWaitForResponse(
            new types.Cell().buildCell(3, resData, circuit.circuitId, true)
        )
    )['3'].Body
    var dnsAdressess = []
    var curOffset = 0
    while (true) {
        var type = response.readUint8(curOffset)
        curOffset += 1
        var bodyLen = response.readUint8(curOffset)
        curOffset += 1
        var body = response.slice(curOffset, curOffset+bodyLen)
        curOffset += bodyLen
        if (type == 4) {
            body = body.readUint8(0) + '.' + body.readUint8(1) + '.' + body.readUint8(2) + '.' + body.readUint8(3)
            dnsAdressess.push({
                type: 'ipv4',
                address: body
            })
        } else {
            if (type == 6) {
                dnsAdressess.push({
                    type: 'ipv6',
                    address: body
                })
            }
        }
        curOffset += 4
        if (response.length >= curOffset) {
            break
        }
    }
    console.log(dnsAdressess)
    return dnsAdressess
}

module.exports = {
    resolveDNS,
    connect
}