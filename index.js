const jose = require('node-jose'),
      parse = require('parse-link-header'),
      url = require('url'),
      fs = require('fs'),
      keystore = jose.JWK.createKeyStore(),
      LE_HOST = 'acme-staging.api.letsencrypt.org'

var cachedKey
function key() {
  if (cachedKey)
    return cachedKey

  return Promise.resolve()
    .then(() => fs.readFileSync('./letsencrypt.key'))
    .catch((err) => {
      if (err.code !== 'ENOENT') {
        err.message = `Failed to read letsencrypt.key file: ${err.message}`
        throw err
      }

      return keystore.generate('RSA', 2048)
        .then((key) => {
          fs.writeFileSync('./letsencrypt.key', JSON.stringify(key.toJSON(true)))
          return key
        })
    })
    .then((data) => jose.JWK.asKey(data))
    .then((key) => cachedKey = key)

  return keystore.generate('RSA', 2048)
    .then((key) => cachedKey = key)
}

var lastNonce
function nonce() {
  if (lastNonce) {
    let nonce = lastNonce
    lastNonce = undefined
    return nonce
  }

  let options = {
        protocol: 'https:',
        host: LE_HOST,
        method: 'HEAD',
        path: '/directory'
      }

  return request(options)
    .then((res) => res.headers['replay-nonce'])
}

function encode(data) {
  if (typeof data === 'object')
    data = JSON.stringify(data)

  return Buffer.from(data).toString('base64').replace(/=/g, '')
}

function request(options, body) {
  return new Promise((resolve, reject) => {
    const lib = (!options.protocol || options.protocol === 'http:') ? require('http') : require('https'),
          request = lib.request(options, (response) => {

      const body = []
      response.on('data', (chunk) => body.push(chunk))
      response.on('end', () => {
        response.body = body.join('')

        if (response.headers['replay-nonce'])
          lastNonce = response.headers['replay-nonce']

        resolve(response)
      })

      response.on('error', (err) => reject(err))
    })

    request.on('error', (err) => reject(err))

    request.end(body)
  })
}

function call(endpoint, data) {
  return Promise.resolve()
    .then(() => Promise.all([nonce(), key()]))
    .then((results) => {
      let [nonce, key] = results,
          signatureOptions = {
            fields: {
              nonce,
              jwk: key.toJSON()
            },
            format: 'flattened'
          }

      return jose.JWS.createSign(signatureOptions, key)
        .update(JSON.stringify(data))
        .final()
    })
    .then((signed) => {
      let options

      if (typeof endpoint === 'string') {
        options = {
          protocol: 'https:',
          host: LE_HOST,
          method: 'POST',
          path: endpoint
        }
      } else {
        options = endpoint
      }

      return request(options, JSON.stringify(signed))
    })
}

function register() {
  return call('/acme/new-reg', {resource: 'new-reg'})
    .then((res) => {
      if (res.statusCode === 409) {
        console.log('letsencrypt agent already exists')
        return
      }

      if (res.statusCode !== 201)
        throw new Error(`Failed to register letsencrypt agent: ${res.body}`)

      let body = JSON.parse(res.body)

      if (body.Status !== 'valid')
        throw new Error(`Failed to register letsencrypt agent: ${res.body}`)

      let tosUrl = parse(res.headers.link)['terms-of-service'].url,
          options = url.parse(res.headers.location)

      options.method = 'POST'

      return call(options, {resource: 'reg', agreement: tosUrl})
        .then((res) => {
          if (res.statusCode !== 202)
            throw new Error(`Failed to accept letsencrypt ToS: ${res.body}`)

          console.log('Registered letsencrypt agent')
        })
    })
}

function newAuthorization(hostname) {
  return call('/acme/new-authz', {resource: 'new-authz', identifier: {type: 'dns', value: hostname}})
    .then((res) => {
      if (res.statusCode !== 201)
        throw new Error(`Failed to generate new authorization attempt: ${res.body}`)

      return JSON.parse(res.body).challenges.find((challenge) => challenge.type === 'http-01')
    })
}

register()
  .then(() => newAuthorization('tv.chasedouglas.net'))
  .then((authz) => console.dir(authz))
