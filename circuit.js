var crypto_utils = require('./crypto_utils')
var crypto = require('crypto')
var tls = require('tls')
var types = require('./cell_types')
var { RelayCell } = require('./relayCell')
var relayDB = require('./relayDB')

var STAGES = 5

class Circuit {
    constructor() {
        this.curStage = 0
        this.storage = crypto_utils.generateKeys()
        this.keyMaterial = crypto.randomBytes(20)
        this.cellHandler = new types.Cell()
        this._use4Len = false
    }

    conectionMessage(message) {
        this.curStage = this.curStage +  1
        console.log("Bootstrapping " + Math.floor((this.curStage/STAGES)*100) + '%: ' + message)
    }

    async writeAndWaitForResponse(data) {
        return new Promise((resolve,reject) => {
            this.responseDataGot = function(data) {
                resolve(data)
            }
            this.socket.write(data)
        })
    }
    

    async connect() {
        while (true) {
            try {
                this.conectionMessage("Finding to socket...")
                var hostData = await relayDB.retrieveRelay()

                this.conectionMessage("Connecting to socket...")
                this.socket = tls.connect({
                    host: hostData.ip,
                    port: hostData.port,
                    timeout: 2000,
                    rejectUnauthorized: false,
                })

                var finishedVal = false
                var failedVal = false

                this.socket.on('error', async () => {
                    failedVal = true
                    finishedVal = true
                })

                this.socket.on('ready', async () => {

                    this.socket.on('data', (res) => {
                        if (this.responseDataGot != undefined) {
                            this.responseDataGot(res)
                        }
                    })
            
                    this.conectionMessage("Connected; sending versions message...")
            
                    var buf = this.cellHandler.buildCell(7, new types.VersionCell([3,4,5]).build(), 0, false)
                    var parsedData = this.cellHandler.decodeCell(await this.writeAndWaitForResponse(buf))
            
                    var netInfo = new types.NetInfo()
                    var netInfoData = parsedData["8"]
                    netInfoData = netInfo.writeResponse(netInfoData)
            
                    netInfoData = new types.Cell().buildCell(8, netInfoData, 0, true)
            
                    var createFast = new types.CreateFast().build(this.keyMaterial)
                    createFast = new types.Cell().buildCell(5, createFast, 0x80000000 , true)
            
                    var sendData = Buffer.concat([netInfoData, createFast])
                    this.conectionMessage("Creating circuit with CREATE_FAST...")
            
                    var createdFast = this.cellHandler.decodeCell(await this.writeAndWaitForResponse(sendData))
                    var mainData = crypto_utils.fromKDF(this.keyMaterial, createdFast['6'].keyMaterial)  
                    this.conectionMessage("Finished")  
                    this.fowardDigest = crypto_utils.sha1Incomplete(mainData.fowardDigest)
                    this.backwardDigest = crypto_utils.sha1Incomplete(mainData.backwardDigest)
                    var resData = new RelayCell().buildBody({
                        RelayCommand: 13,
                        StreamID: 14,
                        Body: Buffer.alloc(0)
                    }, mainData.fowardKey, this.fowardDigest)
                    console.log(resData)
                    var sendWithRes = await this.writeAndWaitForResponse(new types.Cell().buildCell(3, resData, 0x80000000, true))
                    console.log(sendWithRes)
                    finishedVal = true  
                })
                while (true) {
                    if (finishedVal == true) {
                        break
                    }
                    await new Promise(resolve => setTimeout(resolve, 10));
                }
                if (failedVal == false) {
                    break
                }
            } catch(e) {
                console.log("Failed with error; retrying...")
            }
        }
    }
}

module.exports = {
    Circuit
}