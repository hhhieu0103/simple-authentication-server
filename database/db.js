var mongoose = require('mongoose')
var authentication = require('./authentication')

async function connect() {
    await mongoose.connect('mongodb://localhost:27017/simple-authentication')
}

const db = {
    connect,
    disconnect: mongoose.disconnect,
    ...authentication,
}

module.exports = db