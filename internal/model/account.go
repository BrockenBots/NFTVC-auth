package model

type Account struct {
	Id             string
	WalletPub      string
	WalletVerified bool
	Role           string
}

func NewAccount(id string, walletPub string, role string) *Account {
	return &Account{Id: id, WalletPub: walletPub, WalletVerified: false, Role: role}
}
