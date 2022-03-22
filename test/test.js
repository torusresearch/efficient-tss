const assert = require('assert')
// const BN = require('bn.js');
const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const utils = require('../src/utils')
const BN = require('bn.js')

describe('Basic', function () {
  it('should generate private key and public key', function () {
    const privKey = utils.generatePrivate()
    const pubKey = utils.getPublic(privKey)
    const y = ec.g.mul(privKey)
    const xCoord = y.getX().toString(16, 64)
    const yCoord = y.getY().toString(16, 64)
    assert.equal(pubKey.toString('hex'), `04${xCoord}${yCoord}`)
  })
  it('should generate poly and create shares and interpolate', function () {
    const xIntercept = new BN(10)
    const polynomial = utils.generatePolynomial(2, xIntercept)
    const s1 = utils.getShare(polynomial, 1)
    const s2 = utils.getShare(polynomial, 2)
    const s3 = utils.getShare(polynomial, 3)
    const interpolated = utils.lagrangeInterpolation(
      [s1, s2, s3],
      [new BN(1), new BN(2), new BN(3)]
    )
    assert.equal(interpolated.toString(), xIntercept.toString())
  })
  it('should generate t polynomial sharing and reconstruct the secret using a 2t polynomial', function () {
    const xIntercept = new BN(10)
    const polynomial = utils.generatePolynomial(2, xIntercept)
    const s1 = utils.getShare(polynomial, 1)
    const s2 = utils.getShare(polynomial, 2)
    const s3 = utils.getShare(polynomial, 3)
    const s4 = utils.getShare(polynomial, 4)
    const s5 = utils.getShare(polynomial, 5)
    const interpolated = utils.lagrangeInterpolation(
      [s1, s2, s3, s4, s5],
      [new BN(1), new BN(2), new BN(3), new BN(4), new BN(5)]
    )
    assert.equal(interpolated.toString(), xIntercept.toString())
  })
  it('should interpolate in the exponent', function () {
    const xIntercept = new BN(10)
    const y = ec.g.mul(xIntercept)
    const polynomial = utils.generatePolynomial(2, xIntercept)
    const s1 = utils.getShare(polynomial, 1)
    const gS1 = ec.g.mul(s1)
    const s2 = utils.getShare(polynomial, 2)
    const gS2 = ec.g.mul(s2)
    const s3 = utils.getShare(polynomial, 3)
    const gS3 = ec.g.mul(s3)
    const interpolatedPoint = utils.lagrangePointInterpolation(
      [gS1, gS2, gS3],
      [new BN(1), new BN(2), new BN(3)]
    )
    assert.equal(y.getY().toString(16), interpolatedPoint.getY().toString(16))
    assert.equal(y.getX().toString(16), interpolatedPoint.getX().toString(16))
  })
  it.only('should interpolate multiplication of two hierarchical secret sharings', function () {
    const xIntercept = new BN(10)
    const polynomial1 = utils.generatePolynomial(1, xIntercept)
    const s1 = utils.getShare(polynomial1, 1)
    const s2 = utils.getShare(polynomial1, 2)
    const s3 = utils.getShare(polynomial1, 3)
    const polynomial2 = utils.generatePolynomial(2, s3)
    const s31 = utils.getShare(polynomial2, 1)
    const s32 = utils.getShare(polynomial2, 2)
    const s33 = utils.getShare(polynomial2, 3)
    const s34 = utils.getShare(polynomial2, 4)
    const s35 = utils.getShare(polynomial2, 5)

    const xIntercept2 = new BN(7)
    const polynomial3 = utils.generatePolynomial(1, xIntercept2)
    const t1 = utils.getShare(polynomial3, 1)
    const t2 = utils.getShare(polynomial3, 2)
    const t3 = utils.getShare(polynomial3, 3)
    const polynomial4 = utils.generatePolynomial(2, t3)
    const t31 = utils.getShare(polynomial4, 1)
    const t32 = utils.getShare(polynomial4, 2)
    const t33 = utils.getShare(polynomial4, 3)
    const t34 = utils.getShare(polynomial4, 4)
    const t35 = utils.getShare(polynomial4, 5)

    const sNodeInputs = [s31, s32, s33, s34, s35]
    const tNodeInputs = [t31, t32, t33, t34, t35]
    const inputs = []
    for (let i = 0; i < sNodeInputs.length; i++) {
      inputs.push(sNodeInputs[i].mul(tNodeInputs[i]).umod(ec.curve.n))
    }

    const interpolatedst3 = utils.lagrangeInterpolation(inputs, [1, 2, 3, 4, 5].map(i => new BN(i)))
    assert.equal(interpolatedst3.toString(), s3.mul(t3).umod(ec.curve.n).toString())
    const interpolatedMul = utils.lagrangeInterpolation([s1.mul(t1).umod(ec.curve.n), s2.mul(t2).umod(ec.curve.n), interpolatedst3], [1, 2, 3].map(i => new BN(i)))
    assert.equal(interpolatedMul.toString(), xIntercept.mul(xIntercept2).umod(ec.curve.n).toString())
  })
  it('should simulate a threshold signature with nine parties', function () {
    // assume nine servers, t = 4, threshold to sign is t + 1 = 5
    // note that some special unicode characters were used for clarity..
    // normal ECDSA signature: (r,s), where k is random, r = g^k, e = Hash(msg), y = g^x, s = kInv(e + rx)

    // create (t,n)-sharing of private key x
    const x = new BN(utils.generatePrivate())
    const y = ec.curve.g.mul(x)
    const privateKeyPoly = utils.generatePolynomial(4, x)
    // private key shares
    const aShares = []
    for (let i = 0; i < 9; i++) {
      const index = i + 1
      aShares.push(utils.getShare(privateKeyPoly, index))
    }

    // Section 3.2

    // Step 1: create (t,n)-sharing of k
    const k = new BN(utils.generatePrivate())
    const kPoly = utils.generatePolynomial(4, k)
    // k shares
    const kShares = []
    for (let i = 0; i < 9; i++) {
      const index = i + 1
      kShares.push(utils.getShare(kPoly, index))
    }

    // calculate r
    const r = ec.curve.g.mul(k).getX().umod(ec.curve.n)

    // Step 2: create (t,n)-sharing of α and β
    const α = new BN(utils.generatePrivate())
    const β = new BN(utils.generatePrivate())
    const αPoly = utils.generatePolynomial(4, α)
    const βPoly = utils.generatePolynomial(4, β)
    // α and β shares
    const αShares = []
    const βShares = []
    for (let i = 0; i < 9; i++) {
      const index = i + 1
      αShares.push(utils.getShare(αPoly, index))
      βShares.push(utils.getShare(βPoly, index))
    }

    // commitments for α_j and β_j
    // TODO: calculate it for each individual node "locally" instead of getting it directly
    const α_jCommitments = αShares.map(share => {
      return ec.curve.g.mul(share)
    })
    const gˆα_ikPoints = α_jCommitments.map(pt => {
      return pt.mul(k)
    })
    const β_jCommitments = βShares.map(share => {
      return ec.curve.g.mul(share)
    })
    const yˆα_i·gˆβ_iPoints = β_jCommitments.map((pt, i) => {
      return pt.add(y.mul(αShares[i]))
    })

    // Step 3: create a (2t,n)-sharing of 0
    const κPoly = utils.generatePolynomial(8, new BN(0))
    const κShares = []
    for (let i = 0; i < 9; i++) {
      const index = i + 1
      κShares.push(utils.getShare(κPoly, index))
    }

    // Step 4: calculate µ_i and λ_i (note that this is on a (2t,n)-sharing)
    const µShares = []
    const λShares = []
    for (let i = 0; i < 9; i++) {
      µShares.push(αShares[i].mul(kShares[i]).add(κShares[i]).umod(ec.curve.n))
      λShares.push(αShares[i].mul(aShares[i]).add(βShares[i]).umod(ec.curve.n))
    }

    // Step 5: check equality of (2t,n)-interpolated values vs (t,n)-interpolated values
    const µ = utils.lagrangeInterpolation(µShares, [1, 2, 3, 4, 5, 6, 7, 8, 9].map(i => new BN(i)))
    const gˆµ = ec.curve.g.mul(µ)
    const gˆαk = utils.lagrangePointInterpolation(gˆα_ikPoints.slice(0, 5), [1, 2, 3, 4, 5].map(i => new BN(i)))
    assert.equal(gˆµ.getX().toString(16), gˆαk.getX().toString(16))
    const λ = utils.lagrangeInterpolation(λShares, [1, 2, 3, 4, 5, 6, 7, 8, 9].map(i => new BN(i)))
    const gˆλ = ec.curve.g.mul(λ)
    const yˆα_i·gˆβ_i = utils.lagrangePointInterpolation(yˆα_i·gˆβ_iPoints.slice(0, 5), [1, 2, 3, 4, 5].map(i => new BN(i)))
    assert.equal(gˆλ.getX().toString(16), yˆα_i·gˆβ_i.getX().toString(16))

    // Step 6 + Step 7 + Step 8: store precomputes
    const kInverseShares = []
    for (let i = 0; i < 9; i++) {
      kInverseShares.push(µ.invm(ec.curve.n).mul(αShares[i]).umod(ec.curve.n))
    }
    const σShares = []
    for (let i = 0; i < 9; i++) {
      σShares.push(λ.sub(βShares[i]).umod(ec.curve.n).mul(µ.invm(ec.curve.n)).mul(r).umod(ec.curve.n))
    }

    // Step 9: threshold ECDSA, output should be (r,s)
    const sShares = []
    const msgHash = new BN(utils.generatePrivate()) // TODO: use keccak256 to hash message instead
    const e = msgHash
    for (let i = 0; i < 9; i++) {
      sShares.push(kInverseShares[i].mul(e).add(σShares[i]).umod(ec.curve.n))
    }

    // Step 10: interpolate s
    const s = utils.lagrangeInterpolation(sShares.slice(0, 5), [1, 2, 3, 4, 5].map(i => new BN(i)))

    // ECDSA verify should pass
    // TODO: check that ethereum signature verification passes
    const key = ec.keyFromPublic({ x: y.getX().toString(16), y: y.getY().toString(16) })
    assert(key.verify(msgHash, { r: r.toString(16), s: s.toString(16) }))
  })
})
