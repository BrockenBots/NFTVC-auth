package roles

type RoleService struct {
	roles map[string]Role
}

func NewRoleService() *RoleService {
	roleService := &RoleService{roles: make(map[string]Role, 0)}
	roleService.RegisterRoles()
	return roleService
}

func (r *RoleService) hasRole(roleTitle string) bool {
	_, ok := r.roles[roleTitle]
	return ok
}

func (r *RoleService) RegisterRole(role Role) {
	if !r.hasRole(role.Title) {
		r.roles[role.Title] = role
	}
}

func (r *RoleService) HasPermission(role string, permission Permission) bool {
	rl, ok := r.roles[role]
	if !ok {
		return false
	}
	for _, p := range rl.Permissions {
		if permission == p {
			return true
		}
	}
	return false
}
