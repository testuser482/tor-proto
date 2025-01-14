var crypto_utils = require('./crypto_utils')
var crypto = require('crypto')
var tls = require('tls')
var logger = require('./logger')
var request = require('./request')
var types = require('./cell_types')
var { RelayCell } = require('./relayCell')
var relayDB = require('./relayDB')

var STAGES = 5

function handleNum(num) {
    switch(num) {
        case 1:
            return '1st'
        case 2:
            return '2nd'
        case 3:
            return '3rd'
        default:
            return num + 'th'
    }
}


class Circuit {

    constructor() {
        this.state = {}
        this.time = undefined
        this.streamState = 0
        this.curStage = 0
        this.circuitId = Math.floor(Math.random()*10000)
        this.logger = new logger.Logger()
        this.storage = crypto_utils.generateKeys()
        this.keyLayers = []
        this.keyMaterial = crypto.randomBytes(20)
        this.curHop = 0
        this.cellHandler = new types.Cell(this)
        this._use4Len = false
    }

    async retrieveCerts(isExit) {
        while (true) {
            var hostData = await relayDB.retrieveRelay(isExit)
            this.logger.connectionMessage("Using " + hostData.name + "; " + hostData.ip + ":" + hostData.port)
            this.logger.connectionMessage("Fetching base certificates and data from node...")
    
            var finishedVal = undefined
            var cellHandler = new types.Cell()
    
            var socket = tls.connect({
                host: hostData.ip,
                port: hostData.port,
                rejectUnauthorized: false,
            })
            
            var finishedVal = false
            var failedVal = false
    
            socket.on('error', async () => {
                failedVal = true
                finishedVal = true
            })
    
            socket.on('data', async (data) => {
                socket.destroy()
                finishedVal = cellHandler.decodeCell(data)['129']
            })
    
            socket.on('ready', async () => {
                socket.write(cellHandler.buildCell(7, new types.VersionCell([3,4,5]).build(), 0, false))
            })
            var curWait = 0
            var waitTime = false
            while (true) {
                if (finishedVal != false) {
                    break
                }
                if (curWait >= 2000) {
                    this.socket.destroy()
                    failedVal = true
                    break
                } else {
                    curWait += 10
                }
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            if (failedVal == false) {
                return {
                    certs: finishedVal,
                    hostData: hostData
                }
            }
        }
    }

    insertKeyLayer(keys) {
        this.keyLayers.push(keys)
    }

    async writeAndGetAllRes(data) {
        return new Promise((resolve,reject) => {
            var circuit = this
            this.responseDataGot = async function (data) {
                var decodedData = new types.Cell(circuit, true).decodeCell(data)
                if (decodedData['3'] != undefined) {
                    console.log(decodedData['3'].Body.toString())
                } else {
                    if (decodedData['0'] != undefined) {

                    } else {
                        console.log('work found!!')
                        console.log(new RelayCell(circuit).parse(data))
                    }
                }
                    
            }
            this.socket.write(data)
        })
    }

    async writeAndWaitForResponse(data) {
        return new Promise(async (resolve,reject) => {
            var isHadRes = false
            this.responseDataGot = function(data) {
                isHadRes = true
                resolve(data)
            }
            this.socket.write(data)
            var timePassed = 0
            while (true) {
                if (isHadRes == false) {
                    timePassed += 10
                    if (timePassed >= 5000) {
                        break
                    }
                } else {
                    break
                }
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            if (timePassed >= 1000) {
                this.failedVal = true
                this.finishedVal = true
            }
        })
    }

    async tearDown() {
        this.socket.write(this.cellHandler.buildCell(4, Buffer.from([9]), this.circuitId, true))
        this.socket.destroy()
    }
    
    async finishCircuit() {
        return new Promise(async (resolve,reject) => {
            var certData = undefined
            if (this.keyLayers.length == 2) {
                certData = await this.retrieveCerts(true)
            } else {
                certData = await this.retrieveCerts()
            }
            var serverRelayId = undefined
            var legacyKey = undefined

            certData.certs.forEach(function(key) {
                if (key.CERT_TYPE == 7) {
                    serverRelayId = key.KEY
                } else {
                    if (key.CERT_TYPE == 2) {
                        legacyKey = crypto_utils.sha1(key.KEY)
                    }
                }
            })
        
            var connectionKeys = crypto_utils.generateKeys()

            var createCell = new types.CreateCell()

            var handShake = createCell.prepareBody({
                verification: 'circuit extend',
                serverRelayId: serverRelayId,
                onionKey: certData.hostData.publicKey,
                ...connectionKeys.keys
            })
            this.logger.connectionMessage("Fetched; telling the " + handleNum(this.curHop) + " hop to extend circuit")

            var ipData = Buffer.from([certData.hostData.ip.split('.')[0], certData.hostData.ip.split('.')[1], certData.hostData.ip.split('.')[2], certData.hostData.ip.split('.')[3], 0, 0])
            ipData.writeUint16BE(certData.hostData.port, 4)
            
            var dataPrep = {
                NSPEC: [
                    {
                        TYPE: 0,
                        DATA: ipData
                    },
                    {
                        TYPE: 2,
                        DATA: legacyKey
                    },
                    {
                        TYPE: 3,
                        DATA: serverRelayId
                    },
                ]
            }

            dataPrep = new types.ExtendCell().build(dataPrep)
            dataPrep = Buffer.concat([dataPrep, createCell.build(handShake.client_handshake)])
            
            var resData = new RelayCell(this).buildBody({
                RelayCommand: 14,
                StreamID: 0,
                Body: dataPrep
            })

            var resThing = await this.writeAndWaitForResponse(new types.Cell().buildCell(9, resData, this.circuitId, true))
            this.logger.connectionMessage("Finished handshake with " + (this.curHop + 1) + ' hops')


            resThing = this.cellHandler.decodeCell(resThing)
            if (resThing['3'] == undefined) {
                this.failedVal = true
                this.finishedVal = true
            } else {
                var parsed = new types.CreatedCell({
                    state: handShake.state
                }).parse(resThing['3'].returnData.Body)
                this.insertKeyLayer(parsed)
                if (this.keyLayers.length >= 3) {
                    this.logger.connectionMessage("Built circuit")
                    resolve()
                } else {
                    this.curHop += 1
                    this.logger.connectionMessage("Extending to " + (this.curHop + 1) + ' hops')
                    await this.finishCircuit()
                    resolve()
                }
    
            }
        })
    }
    async connectToHost(hostname, port, streamId) {
        return await request.connect(this, hostname, port, streamId)
    }
    async writeTLS(data, streamId) {
        return await request.writeTLS(this, data, streamId)
    }
    async handleCallback(callback) {
        request.handleCallback(this, callback)
    }
    async endRelayStream(streamId) {
        request.endRelayStream(streamId)
    }
    async connect() {
        this.time = new Date()
        try {
            this.logger.connectionMessage("Finding gaurd node...")
            var hostData = await relayDB.retrieveRelay()
            this.storage.keys.onionKey = hostData.publicKey

            this.logger.connectionMessage("Using " + hostData.name + "; " + hostData.ip + ":" + hostData.port)
            this.socket = tls.connect({
                host: hostData.ip,
                port: hostData.port,
                rejectUnauthorized: false,
            })
            
            this.finishedVal = false
            this.failedVal = false

            this.socket.on('error', async () => {
                this.failedVal = true
                this.finishedVal = true
            })

            var waitTime = false

            this.socket.on('ready', async () => {
                waitTime = true
                this.socket.on('data', (res) => {
                    //console.log('recieved data ' + new Uint8Array(res))
                    if (this.responseDataGot != undefined) {
                        this.responseDataGot(res)
                    }
                })
        
                this.logger.connectionMessage("Connected; sending versions message...")
        
                var buf = this.cellHandler.buildCell(7, new types.VersionCell([3,4,5]).build(), 0, false)
                var parsedData = this.cellHandler.decodeCell(await this.writeAndWaitForResponse(buf))

                if (parsedData['129'] == undefined) {
                    this.failedVal = true
                    this.finishedVal = true
                } else {
                    var mainKey = undefined

                    parsedData['129'].forEach(function(key) {
                        if (key.CERT_TYPE == 7) {
                            mainKey = key.KEY
                        }
                    })

                    this.storage.keys.serverRelayId = mainKey
            
                    var netInfo = new types.NetInfo()
                    var netInfoData = parsedData["8"]
                    netInfoData = netInfo.writeResponse(netInfoData)
            
                    this.logger.connectionMessage("Sending handshake...")

                    netInfoData = new types.Cell(this).buildCell(8, netInfoData, 0, true)

                    var createCell = new types.CreateCell()

                    var handShake = createCell.prepareBody({
                        verification: 'circuit extend',
                        ...this.storage.keys
                    })
        
                    this.state = handShake.state

                    var create = new types.Cell(this).buildCell(10, createCell.build(handShake.client_handshake), this.circuitId, true)

                    var handshakeRes = this.cellHandler.decodeCell(await this.writeAndWaitForResponse(Buffer.concat([netInfoData, create])))['11']
                    this.curHop += 1
                    this.logger.connectionMessage("Successfully handshaked; extending circuit to " + (this.curHop + 1) + " hops...")

                    this.insertKeyLayer(handshakeRes)

                    await this.finishCircuit()
                    
                    this.finishedVal = true
                }
            })

            var curWait = 0
            while (true) {
                if (this.finishedVal == true) {
                    break
                }
                if (curWait >= 2000) {
                    if (waitTime == false) {
                        this.socket.destroy()
                        this.failedVal = true
                        break
                    } else {
                        curWait += 10
                    }
                } else {
                    curWait += 10
                }
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            if (this.failedVal == false) {
                return true
            } else {
                return false
            }
        } catch(e) {
            console.log("Failed with error; retrying...")
            return false
        }
    }
}

module.exports = {
    Circuit
}