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

const secureConnection = (req, res, next) => {
  const clientPublicJwk = req.session.clientPublicJwk
  const serverPublicJwk = req.session.serverPublicJwk
  const serverPrivateJwk = req.session.serverPrivateJwk

  if (clientPublicJwk && serverPublicJwk && serverPrivateJwk)
    next()
  else throw new Error('Connection is not secured.')
}

const decryptRequestBody = (req, res, next) => {
  subtle.importKey("jwk", req.session.serverPrivateJwk, rsa, true, ["decrypt"])
    .then(serverPrivateKey => subtle.decrypt(rsa, serverPrivateKey, req.body))
    .then(decryptedBodyAb => {
      const bodyStr = new TextDecoder().decode(decryptedBodyAb)
      req.decryptedBody = JSON.parse(bodyStr)
      next()
    })
}

router.post('/exchangePublicKey', textParser, function (req, res, next) {
  if (!req.body) throw new Error('Client public key not found.')
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

router.post('/signup', [secureConnection, rawParser, decryptRequestBody], function (req, res, next) {
  const pbkdf2Async = util.promisify(crypto.pbkdf2)
  let account = req.decryptedBody
  account.salt = crypto.randomUUID()
  let createdAccount = null

  pbkdf2Async(account.password, account.salt, 2000, 64, 'SHA-256')
    .then(hashedPassword => {
      account.hashedPassword = hashedPassword
      return db.connect()
    })
    .then(() => {
      return db.Account.create([{
        username: account.username,
        email: account.email,
        salt: account.salt,
        password: account.hashedPassword,
        status: 'Created'
      }])
    })
    .then(docs => {
      createdAccount = {
        id: docs[0].id,
        username: docs[0].username,
        email: docs[0].email,
        createdDate: docs[0].createdDate,
        updatedDate: docs[0].updatedDate,
        status: docs[0].status
      }
      return db.disconnect()
    })
    .then(() => encrypt(createdAccount, req.session.clientPublicJwk))
    .then(encryptedAccount => {
      req.session.account = createdAccount
      res.send(Buffer.from(encryptedAccount))
    })
})

async function encrypt(object, jwk) {
  const arrayBuffer = new TextEncoder().encode(JSON.stringify(object))
  const publicKey = await subtle.importKey('jwk', jwk, rsa, true, ['encrypt'])
  const encrypted = await subtle.encrypt(rsa, publicKey, arrayBuffer)
  return encrypted
}

module.exports = router;