package roles

type Permission int

const (
	SIGNUP Permission = iota
	SIGNIN
	SIGNOUT
	GET_ACCOUNT_BY_ID
	GET_ACCOUNT_BY_WALLET_ADDRESS
	VERIFY_SIGNATURE
)
