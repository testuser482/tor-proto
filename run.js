var Circuit = require('./circuit')

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
    console.log('done')
}

run()