package nonce

import (
	"fmt"
	"nftvc-auth/internal/model"
	"nftvc-auth/internal/repository"
	"nftvc-auth/pkg/logger"
	"time"

	"github.com/gofrs/uuid"
)

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
	uuid, _ := uuid.NewV7()
	_ = fmt.Sprintf("%x", uuid.Bytes())

	nonce := model.NewNonce("huy", walletAddress, n.nonceExp)
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
