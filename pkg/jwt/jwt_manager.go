package jwt

import (
	"nftvc-auth/pkg/logger"
	"time"
)

type JwtManager interface {
	GenerateTokens(accountID string, role string) (string, string, error)
	ValidateToken(token string) error
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
}

func NewJwtManager(log logger.Logger, cfg *JwtConfig) *jwtManager {
	return &jwtManager{log: log, cfg: cfg, accessExp: cfg.AccessTokenExp, refreshExp: cfg.RefreshTokenExp}
}
