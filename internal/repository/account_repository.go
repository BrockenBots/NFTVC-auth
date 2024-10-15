package repository

import (
	"nftvc-auth/internal/model"
)

type AccountRepository interface {
	Add(account *model.Account) error
	Update(account *model.Account) error
	// Delete(accountId string) error
	GetById(accountId string) (*model.Account, error)
	GetByWalletAddress(walletAddress string) (*model.Account, error)
}
