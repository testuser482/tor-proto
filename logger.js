var fs = require('fs')

class Logger {
    constructor() {
        this.STAGES = 15
        this.CURSTAGE = 0
    }
    connectionMessage(message) {
        this.CURSTAGE = this.CURSTAGE +  1
        console.log("Bootstrapping " + Math.floor((this.CURSTAGE/this.STAGES)*100) + '%: ' + message)
    }
    resetStages() {
        this.CURSTAGE = 0
    }
}

module.exports = {
    Logger
}