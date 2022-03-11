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
    assert.equal(interpolated.toString(), xIntercept)
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
    assert.equal(interpolated.toString(), xIntercept)
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
  it.only('should simulate a threshold signature with nine parties', function () {
    // assume nine servers, t = 4, threshold to sign is t + 1 = 5

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

    // create (t,n)-sharing of k
    const k = new BN(utils.generatePrivate())
    const kPoly = utils.generatePolynomial(4, k)
    // k shares
    const kShares = []
    for (let i = 0; i < 9; i++) {
      const index = i + 1
      kShares.push(utils.getShare(kPoly, index))
    }

    // calculate r
    const r = ec.curve.g.mul(k).getX()

    // create (t,n)-sharing of α and β
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
    // TODO: calculate it properly instead of getting it directly
    const α_jCommitments = αShares.map(share => {
      return ec.curve.g.mul(share)
    })
    const gα_ikPoints = α_jCommitments.map(pt => {
      return pt.mul(k)
    })
    const β_jCommitments = βShares.map(share => {
      return ec.curve.g.mul(share)
    })
    const yα_igβ_iPoints = β_jCommitments.map((pt, i) => {
      return pt.add(y.mul(αShares[i]))
    })

    // create a (2t,n)-sharing of 0
    const κPoly = utils.generatePolynomial(8, new BN(0))
    const κShares = []
    for (let i = 0; i < 9; i++) {
      const index = i + 1
      κShares.push(utils.getShare(κPoly, index))
    }

    // calculate µ_i and λ_i (note that this is on a (2t,n)-sharing)
    const µShares = []
    const λShares = []
    for (let i = 0; i < 9; i++) {
      µShares.push(αShares[i].mul(kShares[i]).add(κShares[i]).umod(ec.curve.n))
      λShares.push(αShares[i].mul(aShares[i]).add(βShares[i]).umod(ec.curve.n))
    }

    // check equality of (2t,n)-interpolated values vs (t,n)-interpolated values
    const µ = utils.lagrangeInterpolation(µShares, [1, 2, 3, 4, 5, 6, 7, 8, 9].map(i => new BN(i)))
    const gµ = ec.curve.g.mul(µ)
    const gαk = utils.lagrangePointInterpolation(gα_ikPoints.slice(0, 5), [1, 2, 3, 4, 5].map(i => new BN(i)))
    assert.equal(gµ.getX().toString(16), gαk.getX().toString(16))
    const λ = utils.lagrangeInterpolation(λShares, [1, 2, 3, 4, 5, 6, 7, 8, 9].map(i => new BN(i)))
    const gλ = ec.curve.g.mul(λ)
    const yα_igβ_i = utils.lagrangePointInterpolation(yα_igβ_iPoints.slice(0, 5), [1, 2, 3, 4, 5].map(i => new BN(i)))
    assert.equal(gλ.getX().toString(16), yα_igβ_i.getX().toString(16))

    // store precomputes
    const kInverseShares = []
    for (let i = 0; i < 9; i++) {
      kInverseShares.push(µ.invm(ec.curve.n).mul(αShares[i]).umod(ec.curve.n))
    }
    const σShares = []
    for (let i = 0; i < 9; i++) {
      σShares.push(λ.sub(βShares[i]).umod(ec.curve.n).mul(µ.invm(ec.curve.n)).mul(r).umod(ec.curve.n))
    }

    // threshold ECDSA, output should be (r,s)
    const sShares = []
    const msgHash = new BN(utils.generatePrivate())
    for (let i = 0; i < 9; i++) {
      sShares.push(kInverseShares[i].mul(msgHash).add(σShares[i]).umod(ec.curve.n))
    }

    const s = utils.lagrangeInterpolation(sShares.slice(0, 5), [1, 2, 3, 4, 5].map(i => new BN(i)))
    const key = ec.keyFromPrivate(Buffer.from(x.toString(16), 'hex'))
    // const sig = key.sign(msgHash)
    // console.log(sig.r.toString(16), sig.s.toString(16), 'sign')
    // console.log(r.toString(16), s.toString(16))

    assert(key.verify(msgHash, { r: r.toString(16), s: s.toString(16) }))
  })
})
