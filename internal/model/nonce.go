package model

import "time"

type Nonce struct {
	Nonce         string
	WalletAddress string
	Exp           time.Duration
}

func NewNonce(nonce string, walletAddress string, exp time.Duration) *Nonce {
	return &Nonce{Nonce: nonce, WalletAddress: walletAddress, Exp: exp}
}
