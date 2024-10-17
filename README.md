# NFTVC-auth
NFTVC-Auth is an authorization and token management service for the digital profile platform using NFT and Verifiable Credentials. The project is based on authorization via an Ethereum wallet, as well as session management and access tokens using JWT.
# Stack
Golang: The main implementation language
JWT: Generation and validation of access and update tokens
Ethereum: Verification of signatures using the public key of the Ethereum wallet
MongoDB: Data Storage for users and refresh tokens
Redis: A repository for nonces, checking their uniqueness, access token and blacklist tokens
Swagger: Automatic generation of API documentation
# API
1. Sign In With Wallet
POST /api/auth/sign-in

Authorization via wallet, returns nonce for subsequent signature.
Parameters:

WalletPub is the public address of the user's wallet
Answer:

nonce — Generated UUID for signature verification.
2. Verify Signature
POST /api/auth/verify-signature

Wallet signature verification, returns access and refresh tokens.
Parameters:

WalletPub is the public address of the user's wallet
Signature — A signature generated based on nonce
Answer:

access_token — JWT access token
refresh_token — JWT refresh token
3. Refresh Tokens
POST /api/auth/refresh-tokens

Updating tokens with a valid refresh token.
Parameters:

refresh_token — Refresh token
Answer:

access_token — Updated JWT access token
refresh_token — Updated JWT update token
4. Sign Out
POST /api/auth/sign-out

User logout, token revocation.
Parameters:

access_token (in the header) is the JWT token that needs to be revoked.
Answer:

An empty response body for a successful operation.
# Swagger
Access to swagger: http://localhost:<port>/swagger/
# Quickstart
1. git clone <repository_url>
2. Configure the config.yml
3. docker-compose up --build 