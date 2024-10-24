package model

type Account struct {
	Id        string `bson:"_id,omitempty"`
	WalletPub string `bson:"wallet_pub,omitempty"`
	Role      string `bson:"role,omitempty"`
}

func NewAccount(id string, walletPub string, role string) *Account {
	return &Account{Id: id, WalletPub: walletPub, Role: role}
}
