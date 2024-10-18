package repository

import "nftvc-auth/internal/model"

type NonceRepository interface {
	AddNonce(nonce *model.Nonce) error
	GetNonce(walletAddress string) (*model.Nonce, error)
	DeleteNonce(walletAddress string) error
}
