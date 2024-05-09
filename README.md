h1 How to Run

Only data we pass in jwt payload is the user id (jwt.sign({id}))
JWT_SECRET: - Using hs256 encryption for the signature, secret should be at least 32characters long. The longer the better
JWT_EXPIRES_IN - Duration for which jwt token should be considered valid,even if the signature is correct. e.g. logging out the user after a certain period of time - Additional security measure
