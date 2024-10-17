package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"nftvc-auth/internal/model"
	"nftvc-auth/internal/repository"
	"nftvc-auth/pkg/config"
	"nftvc-auth/pkg/logger"
	"os"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
)

type JwtManager interface {
	GenerateTokens(ctx context.Context, accountID string, walletPub string, role string) (string, string, error)
	VerifyToken(context context.Context, accessToken string) (jwt.MapClaims, error)
	RefreshToken(ctx context.Context, refreshToken string) (newAccessToken string, newRefreshToken string, err error)
	IsRevokedToken(ctx context.Context, accountId string, deviceId string, accessToken string) bool
	RevokeToken(subj string) error
}

type JwtConfig struct {
	AccessTokenExp  time.Duration `mapstructure:"accessTokenExp" validate:"required"`
	RefreshTokenExp time.Duration `mapstructure:"refreshTokenExp" validate:"required"`
	PublicKeyPath   string        `mapstructure:"publicKeyPath" validate:"required"`
	PrivateKeyPath  string        `mapstructure:"privateKeyPath" validate:"required"`
}

type jwtManager struct {
	log            logger.Logger
	accessExp      time.Duration
	refreshExp     time.Duration
	jwtRepo        repository.JwtRepository
	publicKeyPath  string
	privateKeyPath string
}

func NewJwtManager(log logger.Logger, cfg *config.Config, jwtRepo repository.JwtRepository) *jwtManager {
	return &jwtManager{
		log:            log,
		accessExp:      cfg.AccessTokenExp,
		refreshExp:     cfg.RefreshTokenExp,
		jwtRepo:        jwtRepo,
		publicKeyPath:  cfg.PublicKeyPath,
		privateKeyPath: cfg.PrivateKeyPath,
	}
}

func (j *jwtManager) GenerateTokens(ctx context.Context, accountID string, walletPub string, role string) (accessToken, refreshToken string, err error) {
	deviceUuid, _ := uuid.NewV7()
	deviceId := deviceUuid.String()
	accessToken, err = j.generateAccessToken(ctx, accountID, walletPub, deviceId, role)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = j.generateRefreshToken(ctx, accountID, walletPub, deviceId, role)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (j *jwtManager) generateAccessToken(ctx context.Context, accountId, walletPub, deviceId, role string) (string, error) {
	jti, _ := uuid.NewV7()
	accountClaims := &model.AccountClaims{
		Jti:       jti.String(),
		Iat:       time.Now().Unix(),
		Exp:       time.Now().Add(j.accessExp).Unix(),
		Sub:       accountId,
		WalletPub: walletPub,
		DeviceId:  deviceId,
		Iss:       "auth.service",
		Role:      role,
	}

	tokenValue, err := j.generateToken(accountClaims)
	if err != nil {
		return "", err
	}

	token := model.NewToken(jti.String(), deviceId, accountId, tokenValue, accountClaims.Exp)

	if err := j.jwtRepo.SaveAccessToken(ctx, token); err != nil {
		return "", err
	}

	return tokenValue, nil
}

func (j *jwtManager) generateRefreshToken(ctx context.Context, accountId, walletPub, deviceId, role string) (string, error) {
	jti, _ := uuid.NewV7()
	accountClaims := &model.AccountClaims{
		Jti:       jti.String(),
		Iat:       time.Now().Unix(),
		Exp:       time.Now().Add(j.accessExp).Unix(),
		Sub:       accountId,
		WalletPub: walletPub,
		DeviceId:  deviceId,
		Iss:       "auth.service",
		Role:      role,
	}

	tokenValue, err := j.generateToken(accountClaims)
	if err != nil {
		return "", err
	}

	token := model.NewToken(jti.String(), deviceId, accountId, tokenValue, accountClaims.Exp)

	if err := j.jwtRepo.SaveRefreshToken(ctx, token); err != nil {
		return "", err
	}

	return tokenValue, nil
}

func (j *jwtManager) generateToken(accountClaims *model.AccountClaims) (string, error) {
	privateKey, err := j.getPrivateKey()
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, accountClaims)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func (j *jwtManager) VerifyToken(ctx context.Context, token string) (jwt.MapClaims, error) {
	publicKey, err := j.getPublicKey()
	if err != nil {
		return nil, err
	}

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		j.log.Debugf("Failed to parse token: %v", err)
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		exp, ok := claims["exp"].(float64)
		if !ok {
			return nil, errors.New("invalid token expiration time")
		}

		if int64(exp) < time.Now().Unix() {
			return nil, errors.New("token is expired")
		}

		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (j *jwtManager) RefreshToken(ctx context.Context, refreshToken string) (newAccessToken string, newRefreshToken string, err error) {
	refreshTokenClaims, err := j.VerifyToken(ctx, refreshToken)
	if err != nil {
		return "", "", err
	}

	jti := refreshTokenClaims["jti"].(string)
	sub := refreshTokenClaims["sub"].(string)
	deviceId := refreshTokenClaims["device_id"].(string)
	walletPub := refreshTokenClaims["wallet_pub"].(string)
	role := refreshTokenClaims["role"].(string)

	newAccessToken, err = j.generateAccessToken(ctx, sub, deviceId, walletPub, role)
	if err != nil {
		return "", "", err
	}

	if err := j.jwtRepo.DeleteRefreshToken(ctx, jti); err != nil {
		return "", "", err
	}

	newRefreshToken, err = j.generateRefreshToken(ctx, sub, walletPub, deviceId, role)
	if err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

func (j *jwtManager) RevokeToken(subj string) error {

	return fmt.Errorf("not impl")
}

func (j *jwtManager) getPublicKey() (*rsa.PublicKey, error) {
	readKey, _ := os.ReadFile(j.publicKeyPath)
	block, _ := pem.Decode(readKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		j.log.Error("failed to parse public key", err)
		return nil, err
	}
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		j.log.Fatalf("not an RSA public key")
	}
	return publicKey, nil
}

func (j *jwtManager) getPrivateKey() (*rsa.PrivateKey, error) {
	readKey, _ := os.ReadFile(j.privateKeyPath)
	block, _ := pem.Decode(readKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the privateKey")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		j.log.Error("failed to parse privateKey", err)
		return nil, err
	}
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		j.log.Fatalf("not an RSA private key")
	}
	return privateKey, nil
}

func (j *jwtManager) IsRevokedToken(ctx context.Context, accountId string, deviceId string, accessToken string) bool {
	return j.jwtRepo.IsRevokedToken(ctx, accountId, deviceId, accessToken)
}
