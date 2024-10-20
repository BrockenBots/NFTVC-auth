package repo

import (
	"context"
	"fmt"
	"nftvc-auth/internal/model"
	"nftvc-auth/pkg/logger"

	"github.com/redis/go-redis/v9"
)

type NonceRedisRepo struct {
	// repository.NonceRepository
	log logger.Logger
	db  *redis.Client
}

func NewNonceRedisRepo(log logger.Logger, db *redis.Client) *NonceRedisRepo {
	return &NonceRedisRepo{log: log, db: db}
}

func (n *NonceRedisRepo) AddNonce(nonce *model.Nonce) error {
	if err := n.db.Set(context.Background(), nonce.WalletAddress, nonce.Nonce, nonce.Exp).Err(); err != nil {
		return fmt.Errorf("failed to save nonce: %v", err)
	}

	return nil
}

func (n *NonceRedisRepo) GetNonce(walletAddress string) (*model.Nonce, error) {
	val, err := n.db.Get(context.Background(), walletAddress).Result()
	if err == redis.Nil {
		n.log.Error("(GetNonce) No nonce found for wallet address: ", walletAddress)
		return nil, fmt.Errorf("nonce not found for wallet address: %s", walletAddress)
	} else if err != nil {
		n.log.Error("(GetNonce) Error retrieving nonce: ", err)
		return nil, fmt.Errorf("error retrieving nonce: %v", err)
	}

	nonce := &model.Nonce{
		WalletAddress: walletAddress,
		Nonce:         val,
	}

	return nonce, nil
}

func (n *NonceRedisRepo) DeleteNonce(walletAddress string) error {
	res := n.db.Del(context.Background(), walletAddress)
	if err := res.Err(); err != nil {
		return err
	}
	return nil
}
