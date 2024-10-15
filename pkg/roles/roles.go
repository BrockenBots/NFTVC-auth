package roles

type Role struct {
	Title       string
	Permissions []Permission
}

var (
	WORKER   Role = Role{"worker", []Permission{SIGNUP, SIGNIN, SIGNOUT, GET_ACCOUNT_BY_ID, GET_ACCOUNT_BY_WALLET_ADDRESS, VERIFY_SIGNATURE}}
	EMPLOYER Role = Role{"employer", []Permission{SIGNUP, SIGNIN, SIGNOUT, GET_ACCOUNT_BY_ID, GET_ACCOUNT_BY_WALLET_ADDRESS, VERIFY_SIGNATURE}}
)

func (r *RoleService) RegisterRoles() {
	r.RegisterRole(WORKER)
	r.RegisterRole(EMPLOYER)
}
