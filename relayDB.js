var fetch = require('node-fetch-commonjs')
var net = require('net');
var fs = require('fs')
const { relative } = require('path')

async function retrieveRelay(isExit) {
    if (!fs.existsSync('./relayDB.json')) {
        console.log(`[DB] Database doesn't exist`)
        console.log(`[DB] Finding server to retrieve, db info from`)
        var relayList = undefined

        await fetch('https://onionoo.torproject.org/details', {
            method: 'GET'
        })
            .then(res => res.json())
            .then(response => {
                relayList = response.relays
            })

        var dataBase = []

        relayList.forEach(function(list) {
            if (list.exit_addresses != undefined) {
                dataBase.push(list)
            }
        })
        
        var info = undefined
        while (true) {
            var db = dataBase[0]
            if (db.exit_addresses != undefined) {
                var address = undefined
                db.exit_addresses.forEach(function(ip) {
                    if (net.isIPv4(ip)) {
                        address = ip
                    }
                })

                console.log('[DB] Attempting to retrieve DB info from ' + address + '; ' + db.nickname)

                await fetch('http://' + address + '/tor/server/all.z', {
                    method: 'GET',
                    signal: AbortSignal.timeout(5000)
                })
                    .then(res => res.text())
                    .then(response => {
                        info = response
                    })
                    .catch(res => {
                        console.log('Failed, attempting other db')
                    })
                if (info != undefined) {
                    if (info.split('router ').length > 2) {
                        break
                    }
                }

            }
        }

        console.log('[DB] Parsing router info...')
        var routers = []
        info.split('router ').forEach(function(routerInfo, index) {
            if (index > 0 && routerInfo.includes('ntor-onion-key')) {
                var name = routerInfo.split(' ')[0]
                var ip = routerInfo.split(' ')[1]
                var port = Number(routerInfo.split(' ')[2])
                var publicKey = routerInfo.split('ntor-onion-key ')[1].split('\n')[0]
                routers.push({
                    name: name,
                    ip: ip,
                    port: port,
                    publicKey, publicKey,
                    isExit: routerInfo.includes('accept')
                })    
            }
        })

        fs.writeFileSync('./relayDB.json', JSON.stringify({
            routers: routers
        }))

        var randomRouter = undefined
        if (isExit == true) {
            var exitRouterList = []
            routers.forEach(function(router) {
                if (router.isExit == true) {
                    exitRouterList.push(router)
                }
            })
            randomRouter = exitRouterList[Math.floor(Math.random()*exitRouterList.length)]
        } else {
            randomRouter = routers[Math.floor(Math.random()*routers.length)]
        }

        return {
            ip: randomRouter.ip,
            port: randomRouter.port,
            name: randomRouter.name,
            publicKey: Buffer.from(randomRouter.publicKey, 'base64')
        }


    } else {
        var routers = String(fs.readFileSync('./relayDB.json'))
        routers = JSON.parse(routers).routers


        var randomRouter = undefined
        if (isExit == true) {
            var exitRouterList = []
            routers.forEach(function(router) {
                if (router.isExit == true) {
                    exitRouterList.push(router)
                }
            })
            randomRouter = exitRouterList[Math.floor(Math.random()*exitRouterList.length)]
        } else {
            randomRouter = routers[Math.floor(Math.random()*routers.length)]
        }

        return {
            ip: randomRouter.ip,
            port: randomRouter.port,
            name: randomRouter.name,
            publicKey: Buffer.from(randomRouter.publicKey, 'base64')
        }
    }
}

module.exports = {
    retrieveRelay
}