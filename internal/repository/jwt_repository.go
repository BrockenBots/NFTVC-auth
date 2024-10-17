package repository

import (
	"context"
	"nftvc-auth/internal/model"
)

type JwtRepository interface {
	SaveAccessToken(ctx context.Context, token *model.Token) error
	SaveRefreshToken(ctx context.Context, token *model.Token) error
	RevokeTokens(ctx context.Context, accountId string, deviceId string, acceptedToken string) error
	IsRevokedToken(ctx context.Context, accountId string, deviceId string, accessToken string) bool
	DeleteRefreshToken(ctx context.Context, accountId string, deviceId string) error
}
