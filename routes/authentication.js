var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var db = require('../database/db')
var crypto = require('crypto')
var util = require('util')

var rawParser = bodyParser.raw();
var textParser = bodyParser.text();
var { subtle } = globalThis.crypto;

const rsa = {
  name: "RSA-OAEP",
  hash: "SHA-256",
}

const rsaKeyGeneration = {
  ...rsa,
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
}

router.post('/exchangePublicKey', textParser, function (req, res, next) {
  req.session.regenerate((error) => {
    console.log(error)
  })
  subtle.generateKey(rsaKeyGeneration, true, ["encrypt", "decrypt"])
    .then(({ publicKey, privateKey }) => {
      const serverPublicJwkPromise = subtle.exportKey("jwk", publicKey)
      const serverPrivateJwkPromise = subtle.exportKey("jwk", privateKey)
      return Promise.all([serverPublicJwkPromise, serverPrivateJwkPromise])
    })
    .then((jwks) => {
      req.session.serverPublicJwk = jwks[0]
      req.session.serverPrivateJwk = jwks[1]
      req.session.clientPublicJwk = req.body
      res.send(req.session.serverPublicJwk)
    })
})

router.post('/signup', rawParser, function (req, res, next) {
  const salt = crypto.randomUUID()
  const pbkdf2Async = util.promisify(crypto.pbkdf2)

  let _account = null
  let _clientPublicKey = null
  let _restrictedAccount = null
  let _hashedPassword = null

  subtle.importKey("jwk", req.session.serverPrivateJwk, rsa, true, ["decrypt"])
    .then(serverPrivateKey => subtle.decrypt(rsa, serverPrivateKey, req.body))
    .then(decryptedAccountAb => {
      const accountStr = new TextDecoder().decode(decryptedAccountAb)
      _account = JSON.parse(accountStr)
      return subtle.importKey('jwk', req.session.clientPublicJwk, rsa, true, ['encrypt'])
    })
    .then(clientPublicKey => {
      _clientPublicKey = clientPublicKey
      return pbkdf2Async(_account.password, salt, 2000, 64, 'SHA-256')
    })
    .then(hashedPassword => {
      _hashedPassword = hashedPassword
      return db.connect()
    })
    .then(() => {
      return db.Account.create([{
        username: _account.username,
        email: _account.email,
        salt: salt,
        password: _hashedPassword,
        status: 'Created'
      }])
    })
    .then(createdAccount => {
      _restrictedAccount = {
        id: createdAccount[0].id,
        username: createdAccount[0].username,
        email: createdAccount[0].email,
        createdDate: createdAccount[0].createdDate,
        updatedDate: createdAccount[0].updatedDate,
        status: createdAccount[0].status
      }
      const encodedAccount = new TextEncoder().encode(JSON.stringify(_restrictedAccount))
      return subtle.encrypt(rsa, _clientPublicKey, encodedAccount)
    })
    .then(encryptedAccount => {
      req.session.account = _restrictedAccount
      res.send(Buffer.from(encryptedAccount))
    })
})

module.exports = router;