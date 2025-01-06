async function run() {
    var Circuit = require('./circuit')
    var main = new Circuit.Circuit()
    await main.connect()
    console.log('done')
}

run()