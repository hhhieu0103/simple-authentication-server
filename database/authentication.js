var mongoose = require('mongoose');
const { Schema, Types } = mongoose

const accountSchema = new Schema({
    username: {
        type: String,
        required: true,
        minlength: 8,
        maxlength: 24,
        unique: true
    },
    email: {
        type: String,
        required: true,
        // https://emailregex.com/
        match: /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        unique: true
    },
    salt: {
        type: Types.UUID,
        required: true
    },
    password: {
        type: Buffer,
        required: true,
    },
    createdDate: {
        type: Date,
        default: Date.now
    },
    updatedDate: Date,
    status: {
        type: String,
        required: true,
        enum: ['Created', 'Actived', 'Disabled', 'Deleted']
    },
});

const Account = mongoose.model('Account', accountSchema);

const Authentication = {
    Account,
}

module.exports = Authentication