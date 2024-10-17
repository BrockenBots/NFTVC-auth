package model

type Account struct {
	Id             string `bson:"_id,omitempty"`
	WalletPub      string `bson:"wallet_pub,omitempty"`
	WalletVerified bool   `bson:"wallet_verified"`
	Role           string `bson:"role,omitempty"`
}

func NewAccount(id string, walletPub string, role string) *Account {
	return &Account{Id: id, WalletPub: walletPub, WalletVerified: false, Role: role}
}
