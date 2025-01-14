const net = require('net');
var Circuit = require('../circuit')
const puppeteer = require('puppeteer');
var curCircuit = undefined

async function run() {
    var main = undefined
    while (true) {
        main = new Circuit.Circuit()
        var isEstablished = await main.connect()
        if (isEstablished == true) {
            break
        } else {
            await main.tearDown()
        }
    }
    return main
}

var usedStreamIds = []

const server = net.createServer((socket) => {
    var streamId = undefined
    var stage = 0
    socket.on('data', async function(data) {
        if (data.readUint8(0) == 5 && stage == 0) {
            stage = 1
            socket.write(Buffer.from([5, 0]))
        } else {
            if (data.readUint8(0) == 5 && stage == 1) {
                var offsetCur = 3
                var type = data.readUint8(offsetCur)
                offsetCur += 1
                if (type == 0x01) {
                    console.log(data)
                } else {
                    var len = data.readUint8(offsetCur)
                    offsetCur += 1
                    var dataHost = data.slice(offsetCur, offsetCur+len)
                    offsetCur += len
                    var port = data.readUint16BE(offsetCur)
                    while (true) {
                        streamId = Math.floor(Math.random()*60000)
                        if (streamId < 1) {
                            streamId = 1
                        }
                        if (usedStreamIds[streamId] == undefined) {
                            break
                        }
                    }

                    var resolved = await curCircuit.connectToHost(String(dataHost), port, streamId)
                    if (resolved.length == 8) {
                        var sendBack = Buffer.from([0x05, 0x00, 0x00, 0x01])
                        sendBack = Buffer.concat([sendBack, resolved.slice(0, 4), Buffer.alloc(2)])
                        sendBack.writeUint16BE(port, sendBack.length-2)
                        stage = 2
                        curCircuit.handleCallback(function(data) {
                            console.log('send back')
                            socket.write(data)
                        })
                        socket.write(sendBack)
                    }
                }
            } else {
                if (stage == 2) {
                    console.log('writing this shi')
                    curCircuit.writeTLS(data, streamId)
                }
            }
        }
    })
    socket.on('close', function() {
        if (streamId != undefined) {
            console.log('closed')
            curCircuit.endRelayStream(streamId)
        }
    })
});

// Listen on port 3000
server.listen(3000, async () => {
    curCircuit = await run()
    var address = server.address();
    console.log(address)
    
    const browser = await puppeteer.launch({
        args: [`--proxy-server=socks5://127.0.0.1:3000`],
    });
    console.log('launcing')
    browser.newPage()
});
