const { JWT, JWK } = require(`jose`)

const pemFile = process.env.JWT_PUBLIC_KEY

const pubKey = JWK.asKey(pemFile)

module.exports = (authorization, desiredClaim, subject, issuer) => {
  const [ _, token ] = authorization.split(` `)

  let decodedToken
  try {
    decodedToken = JWT.verify(token, pubKey, {
      subject,
      issuer
    })
  } catch (e) {
    console.log(`error due to invalid token`)
    return false
  }

  const hasValidClaim = decodedToken.claims.some((tokenClaim) => {
    // "*" claim is all access
    if (tokenClaim === `*`) return true

    if (tokenClaim === desiredClaim) return true

    // Wildcard is valid as last position, to allow all claims below that level
    // For instance, `trello.*` will give all access to all Trello data
    if (tokenClaim.includes(`*`)) {
      const tokenClaimParts = tokenClaim.split(`:`).slice(0, -1)
      const desiredClaimParts = desiredClaim.split(`:`)

      return tokenClaimParts.every((claimPart, index) => {
        return desiredClaimParts[index] === claimPart
      })
    }
  })

  return hasValidClaim
}

