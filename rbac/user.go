package rbac

// User 定义以用户
type User struct {
	UserID   string `json:"user_id"`   // 角色ID
	UserName string `json:"user_name"` // 角色名称
	UserDesc string `json:"user_desc"` // 角色的描述
}
