// The optional compact-JWS delivery path.
//
// The X-KXCO-* header scheme is unchanged and remains the default. This tests
// the second path, and — importantly — that adding it changed nothing about
// the first.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { signBodyJws, verifyBodyJws, JWS_HEADER, createSigner, createVerifier } from '../src/index.js'

const keypair = mlDsa.keypairFromMaster(Buffer.alloc(32, 0x33))
const other = mlDsa.keypairFromMaster(Buffer.alloc(32, 0x44))
const KID = fingerprint(keypair.publicKey)
const BODY = JSON.stringify({ event: 'payment.settled', amount: 100 })

test('a delivery round-trips through the JWS path', () => {
  const token = signBodyJws({
    rawBody: BODY, secretKey: keypair.secretKey, kid: KID,
    event: 'payment.settled', deliveryId: 'dlv_123',
  })
  const result = verifyBodyJws({ token, rawBody: BODY, publicKey: keypair.publicKey, pinnedKid: KID })

  assert.equal(result.valid, true)
  assert.equal(result.kid, KID)
  assert.equal(result.claims.event, 'payment.settled')
  assert.equal(result.claims.jti, 'dlv_123')
})

// The point of a detached payload: the header carries a digest, not a second
// copy of the delivery that a lazy verifier could read instead.
test('the token carries a digest, not the body', () => {
  const token = signBodyJws({ rawBody: BODY, secretKey: keypair.secretKey, kid: KID })
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString())

  assert.equal(typeof claims.body_sha256, 'string')
  assert.equal(claims.body_sha256.length, 64)
  assert.ok(!token.includes('payment.settled'), 'the body must not travel inside the token')
})

test('a token lifted onto a different body fails', () => {
  const token = signBodyJws({ rawBody: BODY, secretKey: keypair.secretKey, kid: KID })
  const result = verifyBodyJws({
    token, rawBody: JSON.stringify({ amount: 999999 }), publicKey: keypair.publicKey,
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'body_mismatch')
})

test('the wrong key fails', () => {
  const token = signBodyJws({ rawBody: BODY, secretKey: keypair.secretKey, kid: KID })
  assert.equal(verifyBodyJws({ token, rawBody: BODY, publicKey: other.publicKey }).valid, false)
})

test('a token naming a key the receiver does not serve is refused', () => {
  const token = signBodyJws({ rawBody: BODY, secretKey: keypair.secretKey, kid: KID })
  const result = verifyBodyJws({
    token, rawBody: BODY, publicKey: keypair.publicKey, pinnedKid: 'ffffffffffffffff',
  })
  assert.equal(result.valid, false)
  assert.match(result.reason, /kid mismatch/)
})

test('a stale delivery is refused', () => {
  const token = signBodyJws({
    rawBody: BODY, secretKey: keypair.secretKey, kid: KID,
    timestamp: Math.floor(Date.now() / 1000) - 3600,
  })
  const result = verifyBodyJws({ token, rawBody: BODY, publicKey: keypair.publicKey })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'timestamp_outside_window')

  // The same delivery inside a wider window is fine.
  assert.equal(
    verifyBodyJws({ token, rawBody: BODY, publicKey: keypair.publicKey, windowSeconds: 7200 }).valid,
    true,
  )
})

test('an audience can be pinned', () => {
  const token = signBodyJws({
    rawBody: BODY, secretKey: keypair.secretKey, kid: KID, audience: 'https://acme.example/hooks',
  })
  assert.equal(
    verifyBodyJws({ token, rawBody: BODY, publicKey: keypair.publicKey, audience: 'https://acme.example/hooks' }).valid,
    true,
  )
  const wrong = verifyBodyJws({
    token, rawBody: BODY, publicKey: keypair.publicKey, audience: 'https://evil.example/hooks',
  })
  assert.equal(wrong.valid, false)
  assert.equal(wrong.reason, 'audience_mismatch')
})

test('malformed input fails closed rather than throwing', () => {
  for (const token of ['', 'a.b', 'not a token', 'a.b.c', null, undefined, 42]) {
    const result = verifyBodyJws({ token, rawBody: BODY, publicKey: keypair.publicKey })
    assert.equal(result.valid, false, JSON.stringify(token))
    assert.equal(typeof result.reason, 'string')
  }
  assert.equal(
    verifyBodyJws({ token: signBodyJws({ rawBody: BODY, secretKey: keypair.secretKey, kid: KID }), rawBody: null, publicKey: keypair.publicKey }).reason,
    'missing_body',
  )
})

test('signing needs a kid, or a public key to derive one from', () => {
  assert.throws(() => signBodyJws({ rawBody: BODY, secretKey: keypair.secretKey }), /pass kid, or publicKey/)
  const token = signBodyJws({ rawBody: BODY, secretKey: keypair.secretKey, publicKey: keypair.publicKey })
  assert.equal(verifyBodyJws({ token, rawBody: BODY, publicKey: keypair.publicKey }).kid, KID)
})

// ── the existing header scheme is untouched ─────────────────────────────────

test('the X-KXCO-* headers are exactly what they were', () => {
  const signer = createSigner({
    hmacSecret: 'shared', pqSecretKey: keypair.secretKey, pqKid: KID,
  })
  const headers = signer.sign(BODY, { event: 'payment.settled', deliveryId: 'dlv_1' })

  // No JWS header appears unless a caller asks for one.
  assert.equal(headers[JWS_HEADER], undefined)
  assert.ok(headers['X-KXCO-Timestamp'])
  assert.ok(headers['X-KXCO-Signature'].startsWith('sha256='))
  assert.ok(headers['X-KXCO-PQ-Signature'])
  assert.equal(headers['X-KXCO-PQ-Kid'], KID)

  const verifier = createVerifier({
    hmacSecret: 'shared', pqPublicKey: keypair.publicKey, pinnedKid: KID, required: 'both',
  })
  const lowered = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  assert.equal(verifier.verify(lowered, BODY).ok, true)
})

// The two paths are independent proofs of the same delivery. A receiver can
// take either, or insist on both.
test('both paths can be attached to one delivery and both verify', () => {
  const signer = createSigner({ pqSecretKey: keypair.secretKey, pqKid: KID })
  const headers = signer.sign(BODY, { event: 'payment.settled' })
  headers[JWS_HEADER] = signBodyJws({
    rawBody: BODY, secretKey: keypair.secretKey, kid: KID, event: 'payment.settled',
  })

  const verifier = createVerifier({ pqPublicKey: keypair.publicKey, pinnedKid: KID, required: 'pq' })
  const lowered = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  assert.equal(verifier.verify(lowered, BODY).ok, true)

  assert.equal(
    verifyBodyJws({ token: headers[JWS_HEADER], rawBody: BODY, publicKey: keypair.publicKey, pinnedKid: KID }).valid,
    true,
  )
})
