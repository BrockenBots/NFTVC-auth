package jwt

import (
	"fmt"
	"nftvc-auth/pkg/logger"
	"nftvc-auth/pkg/repo"
	"time"
)

type JwtManager interface {
	GenerateTokens(accountID string, deviceId string, role string) (string, string, error)
	ValidateToken(accountId string, deviceId string, token string) error
	RefreshToken(refreshToken string) (string, string, error)
	RevokeToken(subj string) error
}

type JwtConfig struct {
	AccessTokenExp  time.Duration
	RefreshTokenExp time.Duration
}

type jwtManager struct {
	log        logger.Logger
	cfg        *JwtConfig
	accessExp  time.Duration
	refreshExp time.Duration
	jwtRepo    repo.JwtRepo
}

func NewJwtManager(log logger.Logger, cfg *JwtConfig) *jwtManager {
	return &jwtManager{log: log, cfg: cfg, accessExp: cfg.AccessTokenExp, refreshExp: cfg.RefreshTokenExp}
}

func (j *jwtManager) GenerateTokens(accountID string, deviceId string, role string) (string, string, error) {
	// accessTokenId, _ := uuid.NewV7()
	// _ = &model.Token{
	// 	Id:        accessTokenId.String(),
	// 	DeviceId:  deviceId,
	// 	AccountId: accountID,
	// 	TokenType: model.AccessToken,
	// 	Token:     "",
	// 	Exp:       j.accessExp,
	// }

	// refreshTokenId, _ := uuid.NewV7()
	// _ = &model.Token{
	// 	Id:        refreshTokenId.String(),
	// 	DeviceId:  deviceId,
	// 	AccountId: accountID,
	// 	TokenType: model.RefreshToken,
	// 	Token:     "",
	// 	Exp:       j.accessExp,
	// }

	return "", "", fmt.Errorf("not impl")
}

// func generateAccessToken

func (j *jwtManager) ValidateToken(accountId string, deviceId string, token string) error {
	return fmt.Errorf("not impl")
}

func (j *jwtManager) RefreshToken(refreshToken string) (string, string, error) {
	return "", "", fmt.Errorf("not impl")
}

func (j *jwtManager) RevokeToken(subj string) error {
	return fmt.Errorf("not impl")
}
