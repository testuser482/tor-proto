var { RelayCell } = require('./relayCell')
var types = require('./cell_types')
const HTTPTag = require('http-tag')
var totalCallbacks = {}

async function connect(circuit, ip, port, streamId) {
    var data = Buffer.concat([Buffer.from(ip), Buffer.from(":"), Buffer.from(port.toString()), Buffer.from([0])])
    console.log(data.toString())
    data = Buffer.concat([data, Buffer.alloc(1)])
    var resData = new RelayCell(circuit).buildBody({
        RelayCommand: 1,
        StreamID: streamId,
        Body: data
    })
    var response = new types.Cell(circuit, true).decodeCell(
        await circuit.writeAndWaitForResponse(
            new types.Cell().buildCell(3, resData, circuit.circuitId, true)
        )
    )
    return response['3'].returnData.Body
}

async function handleTotalCallbacks(callbackThing) {
    if (callbackThing['3'] != undefined) {
        if (Array.isArray(callbackThing['3'])) {
            var totalDataForStreamId = {}
            callbackThing['3'].forEach(function(dat) {
                if (dat.returnData["RelayCommand"] == 2) {
                    console.log('nope')
                    if (totalCallbacks[dat.returnData["StreamID"]] != undefined) {
                        if (totalDataForStreamId[dat.returnData["StreamID"]] != undefined) {
                            totalDataForStreamId[dat.returnData["StreamID"]]  = Buffer.alloc(0)
                        }
                        totalDataForStreamId[dat.returnData["StreamID"]] = Buffer.concat([totalDataForStreamId[dat.returnData["StreamID"]], dat.returnData.Body])
                    }
                }
            })
            for (var key in totalDataForStreamId) {
                if (totalCallbacks[key] != undefined) {
                    totalCallbacks[key](totalDataForStreamId[key])
                }
            }
        } else {
            if (callbackThing['3'].returnData["RelayCommand"] == 2) {
                console.log('nope')
                if (totalCallbacks[callbackThing['3'].returnData["StreamID"]] != undefined) {
                    totalCallbacks[callbackThing['3'].returnData["StreamID"]](callbackThing['3'].returnData.Body)
                }
            }
        }
    }
    console.log('finitu')
}

async function endRelayStream(streamId) {
    var resData2 = new RelayCell(circuit).buildBody({
        RelayCommand: 3,
        StreamID: streamId,
        Body: Buffer.from([6])
    })
    
    circuit.socket.write(circuit.cellHandler.buildCell(3, resData2, circuit.circuitId, true))
}

async function resolveDNS(circuit, name, streamId) {
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
    )['3'].returnData.Body
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
            var bodyNew = body.readUint8(0) + '.' + body.readUint8(1) + '.' + body.readUint8(2) + '.' + body.readUint8(3)
            dnsAdressess.push({
                type: 'ipv4',
                address: bodyNew,
                rawAddress: body
            })
        } else {
            if (type == 6) {
                dnsAdressess.push({
                    type: 'ipv6',
                    rawAddress: body
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

async function writeTLS(circuit, data, streamId) {
    if (data.length > 498) {
        var len = (data.length/498)
        var totalCircuitBody = Buffer.alloc(0)
        if (len > Math.floor(len)) {
            var curOffset = 0
            for (var i = 0; i < Math.floor(len); i ++) {
                var resData2 = new RelayCell(circuit).buildBody({
                    RelayCommand: 2,
                    StreamID: streamId,
                    Body: data.slice(curOffset, curOffset+498)
                })
                curOffset += 498
                
                totalCircuitBody = Buffer.concat([totalCircuitBody, circuit.cellHandler.buildCell(3, resData2, circuit.circuitId, true)])
            }
            var resData2 = new RelayCell(circuit).buildBody({
                RelayCommand: 2,
                StreamID: streamId,
                Body: data.slice(curOffset)
            })
            
            totalCircuitBody = Buffer.concat([totalCircuitBody, circuit.cellHandler.buildCell(3, resData2, circuit.circuitId, true)])
        } else {
            var curOffset = 0
            for (var i = 0; i < Math.floor(len); i ++) {
                var resData2 = new RelayCell(circuit).buildBody({
                    RelayCommand: 2,
                    StreamID: streamId,
                    Body: data.slice(curOffset, curOffset+498)
                })
                curOffset += 498
                
                totalCircuitBody = Buffer.concat([totalCircuitBody, circuit.cellHandler.buildCell(3, resData2, circuit.circuitId, true)])
            }
        }
        circuit.socket.write(totalCircuitBody)
    } else {
        var resData2 = new RelayCell(circuit).buildBody({
            RelayCommand: 2,
            StreamID: streamId,
            Body: data
        })

        circuit.socket.write(circuit.cellHandler.buildCell(3, resData2, circuit.circuitId, true))
    }
}

async function handleCallback(circuit, callback, streamId) {
    totalCallbacks[streamId] = callback
}

module.exports = {
    resolveDNS,
    connect,
    handleTotalCallbacks,
    endRelayStream,
    handleCallback,
    writeTLS
}