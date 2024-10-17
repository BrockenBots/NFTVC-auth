package nonce

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"nftvc-auth/internal/model"
	"nftvc-auth/internal/repository"
	"nftvc-auth/pkg/logger"
	"time"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

type NonceManager interface {
	GenerateNonce(walletAddress string) (string, error)
	GetNonce(walletAddress string) (*model.Nonce, error)
}

type NonceConfig struct {
	NonceExp time.Duration `mapstructure:"exp" validate:"required"`
}

type nonceManager struct {
	log       logger.Logger
	nonceExp  time.Duration
	nonceRepo repository.NonceRepository
}

func NewNonceManager(log logger.Logger, cfg *NonceConfig, nonceRepo repository.NonceRepository) *nonceManager {
	return &nonceManager{log: log, nonceExp: cfg.NonceExp, nonceRepo: nonceRepo}
}

func (n *nonceManager) GenerateNonce(walletAddress string) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}

	nonceValue := hex.EncodeToString(bytes)

	nonce := model.NewNonce(nonceValue, walletAddress, n.nonceExp)
	if err := n.nonceRepo.AddNonce(nonce); err != nil {
		return "", err
	}

	return nonce.Nonce, nil
}

func (n *nonceManager) GetNonce(walletAddress string) (*model.Nonce, error) {
	nonce, err := n.nonceRepo.GetNonce(walletAddress)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}
