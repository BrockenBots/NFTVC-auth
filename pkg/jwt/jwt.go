package jwt

type AccountClaims struct {
	tokenType     TokenType
	iat           uint64
	exp           uint64
	sub           string
	walletAddress string
	iss           string
	role          string
}

type TokenType string

var (
	accessToken  TokenType = "accessToken"
	refreshToken TokenType = "refreshToken"
)
