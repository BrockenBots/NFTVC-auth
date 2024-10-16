package response

type SignInWithWalletResponse struct {
	Nonce string `json:"nonce" validate:"required"`
}

type VerifySignatureResponse struct {
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type ErrorResponse struct {
	Error string `json:"error" validate:"required"`
}
