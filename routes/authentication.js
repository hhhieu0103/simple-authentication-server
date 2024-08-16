var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var db = require('../database/db')
var crypto = require('crypto')
var util = require('util');

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

const pbkdf2Async = util.promisify(crypto.pbkdf2)

const secureConnection = (req, res, next) => {
  const clientPublicJwk = req.session.clientPublicJwk
  const serverPublicJwk = req.session.serverPublicJwk
  const serverPrivateJwk = req.session.serverPrivateJwk

  if (clientPublicJwk && serverPublicJwk && serverPrivateJwk)
    next()
  else res.status(428).end()
}

const decryptRequestBody = async (req, res, next) => {
  const serverPrivateKey = await subtle.importKey("jwk", req.session.serverPrivateJwk, rsa, true, ["decrypt"])
  const decryptedBodyAb = await subtle.decrypt(rsa, serverPrivateKey, req.body)
  const bodyStr = new TextDecoder().decode(decryptedBodyAb)
  req.decryptedBody = JSON.parse(bodyStr)
  next()
}

router.post('/exchangePublicKey', textParser, async function (req, res, next) {
  if (!req.body) {
    res.status(422).send('Missing client public key.')
    return
  }
  const { publicKey, privateKey } = await subtle.generateKey(rsaKeyGeneration, true, ["encrypt", "decrypt"])
  const serverPublicJwk = await subtle.exportKey("jwk", publicKey)
  const serverPrivateJwk = await subtle.exportKey("jwk", privateKey)
  req.session.serverPublicJwk = serverPublicJwk
  req.session.serverPrivateJwk = serverPrivateJwk
  req.session.clientPublicJwk = req.body
  res.cookie('serverPublicJwkStr', JSON.stringify(serverPublicJwk), { expires: req.session.cookie.expires })
  res.end()
})

router.post('/signup', [secureConnection, rawParser, decryptRequestBody], async function (req, res, next) {
  let account = req.decryptedBody
  const salt = crypto.randomUUID()
  const hashedPassword = await pbkdf2Async(account.password, salt, 2000, 64, 'SHA-256')
  await db.connect()
  try {
    var docs = await db.Account.create([{
      username: account.username,
      email: account.email,
      salt: salt,
      password: hashedPassword,
      status: 'Created'
    }])
  } catch (err) {
    res.status(409)
    if (err.keyValue.email)
      res.send('Email is already in use')
    else if (err.keyValue.username)
      res.send('Username is already in use')
    else res.send('Cannot create new account')
    return
  }
  await db.disconnect()
  const createdAccount = {
    id: docs[0].id,
    username: docs[0].username,
    email: docs[0].email,
    createdDate: docs[0].createdDate,
    updatedDate: docs[0].updatedDate,
    status: docs[0].status
  }
  const encryptedAccount = await encrypt(createdAccount, req.session.clientPublicJwk)
  req.session.account = createdAccount
  req.session.isLogedIn = true
  req.session.maxAge = req.session.originalMaxAge
  res.send(Buffer.from(encryptedAccount))
})

router.post('/login', [secureConnection, rawParser, decryptRequestBody], async function (req, res, next) {
  const loginInfo = req.decryptedBody
  if (!loginInfo) {
    res.status(422).send('Missing login info')
    return
  }
  else if (!loginInfo.account) {
    res.status(422).send('Missing email or username')
    return
  }
  else if (!loginInfo.password) {
    res.status(422).send('Missing password')
    return
  }

  await db.connect()
  const account = await db.Account.findOne({
    $or: [
      { email: loginInfo.account },
      { username: loginInfo.account }
    ]
  })
  await db.disconnect()
  if (account == null) {
    res.status(401).send('Incorrect account')
    return
  }
  const hashedPassword = await pbkdf2Async(loginInfo.password, account.salt, 2000, 64, 'SHA-256')

  if (Buffer.compare(hashedPassword, account.password) != 0) {
    res.status(401).send('Incorrect password')
    return
  }

  const accountInfo = {
    id: account.id,
    username: account.username,
    email: account.email,
    status: account.status,
    createdDate: account.createdDate,
    updatedDate: account.updatedDate
  }
  const encrypted = await encrypt(accountInfo, req.session.clientPublicJwk)
  req.session.account = accountInfo
  req.session.isLogedIn = true
  if (loginInfo.keepLogin) req.session.cookie.maxAge = null
  res.send(Buffer.from(encrypted))
})

router.post('/logout', function (req, res, next) {
  res.clearCookie()
  req.session.destroy((err) => {
    if (err) next(err)
    res.end()
  })
})

router.get('/isLogedIn', async function (req, res, next) {
  // if (req.session.isLogedIn) {
  //   await db.connect()
  //   const account = await db.Account.findById(req.session.account.id)
  //   await db.disconnect()
  //   if (account == null) {
  //     res.status(401).send('Unable to retrieve account info.')
  //   } else {
  //     req.session.account = account
  //     const encrypted = await encrypt(account, req.session.clientPublicJwk)
  //     res.send(Buffer.from(encrypted))
  //   }
  // } else {
  //   res.send(false)
  // }
  res.send(req.session.isLogedIn ? true : false)
})

async function encrypt(object, jwk) {
  const arrayBuffer = new TextEncoder().encode(JSON.stringify(object))
  const publicKey = await subtle.importKey('jwk', jwk, rsa, true, ['encrypt'])
  const encrypted = await subtle.encrypt(rsa, publicKey, arrayBuffer)
  return encrypted
}

module.exports = router;