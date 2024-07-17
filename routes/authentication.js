var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');

var rawParser = bodyParser.raw();
var textParser = bodyParser.text();
var { subtle } = globalThis.crypto;

const rsaCryptoObj = {
  name: "RSA-OAEP",
  hash: "SHA-256",
}

const rsaGenerationObj = {
  ...rsaCryptoObj,
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
}

router.get('/test', function (req, res, next) {
  res.send('hello')
})

router.get('/getServerPublicKey', function (req, res, next) {
  if (req.session.exportedPublicKey) {
    res.send(req.session.exportedPublicKey)
  } else {
    subtle.generateKey(
      rsaGenerationObj, true, ["encrypt", "decrypt"]
    ).then(({ publicKey, privateKey }) => {
      // Export the keys for transfering and storing
      const exportedPublicKeyPromise = subtle.exportKey("jwk", publicKey)
      const exportedPrivateKeyPromise = subtle.exportKey("jwk", privateKey)
      // Wait for the exporting processes to finish
      Promise.all([exportedPublicKeyPromise, exportedPrivateKeyPromise])
        .then((exportedKeys) => {
          req.session.exportedPublicKey = exportedKeys[0]
          req.session.exportedPrivateKey = exportedKeys[1]
          // Send the public key to client for encryption
          res.send(req.session.exportedPublicKey)
        }).catch(err => {
          console.log(err)
        })
    }).catch((err) => {
      res.send(err)
    })
  }
});

router.post('/exchangePublicKey', textParser, function (req, res, next) {
  req.session.regenerate((error) => {
    console.log(error)
  })

  // Generate server keys
  subtle.generateKey(
    rsaGenerationObj, true, ["encrypt", "decrypt"]
  ).then(({ publicKey, privateKey }) => {
    // Export the keys for transfering and storing
    const serverPublicJwkPromise = subtle.exportKey("jwk", publicKey)
    const serverPrivateJwkPromise = subtle.exportKey("jwk", privateKey)
    // Wait for the exporting processes to finish
    Promise.all([serverPublicJwkPromise, serverPrivateJwkPromise])
      .then((jwks) => {
        // Store the server generated keys and the client public key
        req.session.serverPublicJwk = jwks[0]
        req.session.serverPrivateJwk = jwks[1]
        req.session.clientPublicJwk = req.body
        // Send the public key to client for encryption
        res.send(req.session.serverPublicJwk)
      }).catch(error => {
        console.log(error)
      })
  }).catch((error) => {
    console.log(error)
  })
})

router.post('/signup', rawParser, function (req, res, next) {
  subtle.importKey("jwk", req.session.exportedPrivateKey, rsaCryptoObj, true, ["decrypt"])
    .then(privateKey => {
      const encryptedAccount = req.body
      subtle.decrypt(rsaCryptoObj, privateKey, encryptedAccount)
        .then(decryptedAccountAb => {
          const account = new TextDecoder().decode(decryptedAccountAb)
          res.send('Pass')
        })
    })
})

module.exports = router;