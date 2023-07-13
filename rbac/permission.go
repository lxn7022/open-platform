// 本文件定义了RBAC模型中Permission模块的实现。
// Object：定义权限控制的对象，按粒度大小，Object可以是一个功能，一个模块、一个子系统等
// Operation：权限控制的对所支持的操作
// Permission：是一个Object和Action之间的矩阵，定义了可以对一个对象执行什么操。
// RBAC规范：https://profsandhu.com/journals/tissec/ANSI+INCITS+359-2004.pdf

package rbac

import (
	"fmt"
	"sync"
)

// Object 定义权限控制的对象
type Object struct {
	ID   uint32 `json:"id"`   // 操作对象ID
	Name string `json:"name"` // 操作对象名称
	Desc string `json:"desc"` // 操作对象的其它信息
}

// Operation 权限控制的对象所支持的操作
type Operation struct {
	ID   uint32 `json:"id"`   // 操作ID
	Name Action `json:"name"` // 操作名称
	Desc string `json:"desc"` // 操作的其它信息
}

// Action 用来指定Operation名称
type Action string

const (
	// None 空
	None Action = ""
	// Create 创建
	Create Action = "create"
	// Read 读取
	Read Action = "read"
	// Update 更新
	Update Action = "update"
	// Delete 删除
	Delete Action = "delete"
	// CRUD =create+read+update+delete
	CRUD Action = "crud"
	// Download 下载
	Download = "download"
	// Upload 上传
	Upload = "upload"
	// Dump 导出数据
	Dump = "dump"
)

// OperationSet 将操作ID构成一个集合
type OperationSet struct {
	sync.Mutex
	opSet map[uint32]bool
}

// NewOperationSet 生成OperationSet实例
func NewOperationSet() *OperationSet {
	return &OperationSet{
		opSet: map[uint32]bool{},
	}
}

// AddOperation 新增一个操作对象
func (p *OperationSet) AddOperation(op *Operation) {
	p.Lock()
	defer p.Unlock()
	p.opSet[op.ID] = true
}

// DelOperation 删除一个操作对象
func (p *OperationSet) DelOperation(op *Operation) {
	p.Lock()
	defer p.Unlock()
	delete(p.opSet, op.ID)
}

// HasOperation 判断是否存在一个操作对象
func (p *OperationSet) HasOperation(op *Operation) bool {
	p.Lock()
	defer p.Unlock()
	_, ok := p.opSet[op.ID]
	return ok
}

// Permission 权限控制的对所支持的操作
type Permission struct {
	ID         uint32                   `json:"perm_id"`     // 权限ID
	Name       string                   `json:"perm_name"`   // 权限名称
	PermMatrix map[uint32]*OperationSet `json:"perm_matrix"` // 权限矩阵，用来表示Object*Operation操作权限对应关系. key: Object.ID
	sync.Mutex
}

// NewPermission 生成Permission实例
func NewPermission(id uint32, name string) *Permission {
	return &Permission{
		ID:         id,
		Name:       name,
		PermMatrix: make(map[uint32]*OperationSet),
	}
}

// AddPermission 新增一个操作对象
func (p *Permission) AddPermission(ob *Object, op *Operation) bool {
	p.Lock()
	defer p.Unlock()

	if ob == nil || op == nil {
		return false
	}
	if _, ok := p.PermMatrix[ob.ID]; !ok {
		p.PermMatrix[ob.ID] = NewOperationSet()
	}

	p.PermMatrix[ob.ID].AddOperation(op)
	return true
}

// DelPermission 删除一个操作对象。如果不传入op，则清空所有权限。
func (p *Permission) DelPermission(ob *Object, op *Operation) bool {
	p.Lock()
	defer p.Unlock()

	if ob == nil {
		return false
	}
	if op == nil {
		delete(p.PermMatrix, ob.ID)
		return true
	}

	if _, ok := p.PermMatrix[ob.ID]; !ok {
		return false
	}

	p.PermMatrix[ob.ID].DelOperation(op)
	return true
}

// HasPermission 判断是否存在一个操作对象
func (p *Permission) HasPermission(ob *Object, op *Operation) bool {
	p.Lock()
	defer p.Unlock()

	if _, ok := p.PermMatrix[ob.ID]; !ok {
		return false
	}

	return p.PermMatrix[ob.ID].HasOperation(op)
}

// String 格式化输出
func (p *Permission) String() string {
	return fmt.Sprintf("(permID:%v,permName:%v)", p.ID, p.Name)
}
