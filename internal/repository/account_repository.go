package repository

import (
	"context"
	"nftvc-auth/internal/model"
)

type AccountRepository interface {
	Add(ctx context.Context, account *model.Account) error
	Update(ctx context.Context, account *model.Account) error
	GetById(ctx context.Context, accountId string) (*model.Account, error)
	GetByWalletAddress(ctx context.Context, walletAddress string) (*model.Account, error)
}
