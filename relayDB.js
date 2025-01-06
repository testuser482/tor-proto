var fetch = require('node-fetch-commonjs')
var fs = require('fs')
const { relative } = require('path')

async function retrieveRelay() {
    if (!fs.existsSync('./relayDB.json')) {
        console.log(`[DB] Database doesn't exist`)
        console.log(`[DB] Retrieving DB from TOR; this takes a bit, be patient!`)
        var dataBase = undefined

        await fetch('https://onionoo.torproject.org/details', {
            method: 'GET'
        })
            .then(res => res.json())
            .then(response => {
                dataBase = response.relays
            })
        
        fs.writeFileSync('./relayDB.json', JSON.stringify({
            relays: dataBase
        }))

        var relay = undefined
        while (true) {
            relay = dataBase[Math.floor(Math.random()*dataBase.length)]
            if (relay.or_addresses != undefined) {
                break
            }
        }
        var address = relay.or_addresses[Math.floor(Math.random()*relay.or_addresses.length)]
        if (relay.nickname != undefined) {
            console.log('[DB] Chose ' + relay.nickname + '; address: ' + address)
        }
        return {
            ip: address.split(':')[0],
            port: address.split(':')[1]
        }
    } else {
        console.log('[DB] Using existing cached database')
        var dataBase = String(fs.readFileSync('./relayDB.json'))
        dataBase = JSON.parse(dataBase).relays

        var relay = undefined
        while (true) {
            relay = dataBase[Math.floor(Math.random()*dataBase.length)]
            if (relay.or_addresses != undefined) {
                break
            }
        }
        var address = relay.or_addresses[Math.floor(Math.random()*relay.or_addresses.length)]
        if (relay.nickname != undefined) {
            console.log('[DB] Chose ' + relay.nickname + '; address: ' + address)
        }
        return {
            ip: address.split(':')[0],
            port: address.split(':')[1]
        }
    }
}

module.exports = {
    retrieveRelay
}