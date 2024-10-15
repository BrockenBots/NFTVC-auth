package repo

import (
	"context"
	"fmt"
	"nftvc-auth/internal/model"
	"nftvc-auth/internal/repository"
	"nftvc-auth/pkg/logger"

	"github.com/jackc/pgx/v5"
)

type PostgresAccountRepo struct {
	repository.AccountRepository
	log logger.Logger
	db  *pgx.Conn
}

func NewPostgresAccountRepo(log logger.Logger, db *pgx.Conn) *PostgresAccountRepo {
	return &PostgresAccountRepo{log: log, db: db}
}

func (p *PostgresAccountRepo) Add(account *model.Account) error {
	query := `INSERT INTO accounts (id, wallet_pub, wallet_verified, role)
			  VALUES ($1, $2, $3, $4)`
	_, err := p.db.Exec(context.Background(), query, account.Id, account.WalletPub, account.WalletVerified, account.Role)
	if err != nil {
		p.log.Debugf("Err by add account: %v", err)
	}
	return err
}

func (p *PostgresAccountRepo) Update(account *model.Account) error {
	query := `UPDATE accounts SET wallet_pub = $1, wallet_verified = $2, role = $3 WHERE id = $4`
	_, err := p.db.Exec(context.Background(), query, account.WalletPub, account.WalletVerified, account.Role, account.Id)
	if err != nil {
		p.log.Debugf("Err by update account: %v", err)
	}
	return err
}

func (p *PostgresAccountRepo) GetById(accountId string) (*model.Account, error) {
	query := `SELECT * FROM accounts WHERE id = $1`
	row := p.db.QueryRow(context.Background(), query, accountId)
	var account model.Account

	if err := row.Scan(account.Id, account.WalletPub, account.WalletVerified, account.Role); err != nil {
		if err == pgx.ErrNoRows {
			p.log.Debugf("(GetById) Not found")
			return nil, fmt.Errorf("not found")
		}

		return nil, err
	}

	return &account, nil
}

func (p *PostgresAccountRepo) GetByWalletAddress(walletAddress string) (*model.Account, error) {
	query := `SELECT * FROM accounts WHERE wallet_pub = $1`
	row := p.db.QueryRow(context.Background(), query, walletAddress)

	var account model.Account

	if err := row.Scan(account.Id, account.WalletPub, account.WalletVerified, account.Role); err != nil {
		if err == pgx.ErrNoRows {
			p.log.Debugf("(GetById) Not found")
			return nil, fmt.Errorf("not found")
		}

		return nil, err
	}

	return &account, nil
}
