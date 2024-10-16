package requests

type SignInWithWalletRequest struct {
	WalletPub string `json:"wallet_pub" validate:"required,eth_addr"`
}

type SignOutRequest struct {
}

type VerifySignatureRequest struct {
	WalletPub string `json:"wallet_pub" validate:"required,eth_addr"`
	Signature string `json:"signature" validate:"required"`
}
