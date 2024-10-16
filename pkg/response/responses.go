package response

type SignInWithWalletResponse struct {
	Nonce string `json:"nonce"`
}

type VerifySignatureResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
