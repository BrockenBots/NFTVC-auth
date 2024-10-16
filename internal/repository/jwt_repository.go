package repository

import "nftvc-auth/internal/model"

type JwtRepository interface {
	SaveAccessToken(token model.Token) error
	SaveRefreshToken(token model.Token) error
	RevokeTokens(accountId string, deviceId string) error
	ExistTokenInBlacklist(token string) bool
	IsActiveAccessToken(token string) bool
}
