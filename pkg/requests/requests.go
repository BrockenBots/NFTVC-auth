package requests

type SignInWithWalletRequest struct {
	WalletPub string `json:"wallet_pub" validate:"required,eth_addr"`
}

type RefreshTokensRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type VerifySignatureRequest struct {
	WalletPub string `json:"wallet_pub" validate:"required,eth_addr"`
	Signature string `json:"signature" validate:"required"`
}

type SignOutRequest struct {
}
