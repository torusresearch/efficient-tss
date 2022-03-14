const { generatePrivate, getPublic } = require('@toruslabs/eccrypto')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const BN = require('bn.js')
const generatePolynomial = function (degree, xIntercept) {
  const res = []
  let i = 0
  if (xIntercept !== undefined) {
    res.push(xIntercept)
    i++
  }
  for (; i < degree; i++) {
    res.push(new BN(generatePrivate()))
  }
  return res
}
const getShare = function (polynomial, index) {
  let res = new BN(0)
  for (let i = 0; i < polynomial.length; i++) {
    const term = polynomial[i].mul((new BN(index)).pow(new BN(i)))
    res = res.add(term.umod(ec.curve.n))
  }
  return res
}
const lagrangeInterpolation = function (shares, nodeIndex) {
  if (shares.length !== nodeIndex.length) {
    return null
  }
  let secret = new BN(0)
  for (let i = 0; i < shares.length; i += 1) {
    let upper = new BN(1)
    let lower = new BN(1)
    for (let j = 0; j < shares.length; j += 1) {
      if (i !== j) {
        upper = upper.mul(nodeIndex[j].neg())
        upper = upper.umod(ec.curve.n)
        let temp = nodeIndex[i].sub(nodeIndex[j])
        temp = temp.umod(ec.curve.n)
        lower = lower.mul(temp).umod(ec.curve.n)
      }
    }
    let delta = upper.mul(lower.invm(ec.curve.n)).umod(ec.curve.n)
    delta = delta.mul(shares[i]).umod(ec.curve.n)
    secret = secret.add(delta)
  }
  return secret.umod(ec.curve.n)
}

const lagrangePointInterpolation = function (points, nodeIndex) {
  if (points.length !== nodeIndex.length) {
    return null
  }
  let res = ec.curve.point(null, null)
  for (let i = 0; i < points.length; i += 1) {
    let upper = new BN(1)
    let lower = new BN(1)
    for (let j = 0; j < points.length; j += 1) {
      if (i !== j) {
        upper = upper.mul(nodeIndex[j].neg())
        upper = upper.umod(ec.curve.n)
        let temp = nodeIndex[i].sub(nodeIndex[j])
        temp = temp.umod(ec.curve.n)
        lower = lower.mul(temp).umod(ec.curve.n)
      }
    }
    const delta = upper.mul(lower.invm(ec.curve.n)).umod(ec.curve.n)
    const deltaPoint = points[i].mul(delta)
    res = res.add(deltaPoint)
  }
  return res
}

module.exports = {
  generatePrivate,
  getPublic,
  generatePolynomial,
  getShare,
  lagrangeInterpolation,
  lagrangePointInterpolation
}
