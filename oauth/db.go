package oauth

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/thoas/go-funk"
)

const (
	// 大小票过期时间
	TokenExpiry   = time.Minute * 10
	RefreshExpiry = time.Hour * 24 * 14
)

// MerchantDB 存储商户的数据库
type MerchantDB interface {
	Read(merchantID string) (*Merchant, error)
	Delete(merchantID string) error
	Create(merchant *Merchant) error
	Update(merchant *Merchant) error
}

// TokenDB 存储Token的数据库
type TokenDB interface {
	CreateToken(appID string, appSecret string) (*Token, error)
	DeleteToken(accessToken string) error
	GetToken(accessToken string) (*Token, error)
	VerifyToken(accessToken string) error
	RefreshToken(accessToken string) (string, error)
}

// BackendMerchantDB 实现MerchantDB接口的后端数据库，仅示意
type BackendMerchantDB struct {
	merchantStore map[string]*Merchant // key:merchantID, value:*Merchant
}

// NewBackendMerchantDB 生成BackendMerchantDB实例
func NewBackendMerchantDB() *BackendMerchantDB {
	return &BackendMerchantDB{map[string]*Merchant{}}
}

// Read 通过merchantID从DB获取Merchant实例
func (mdb *BackendMerchantDB) Read(merchantID string) (*Merchant, error) {
	m, ok := mdb.merchantStore[merchantID]
	if !ok {
		return nil, fmt.Errorf("this merchant not exist:%s", merchantID)
	}
	return m, nil
}

// Delete 通过merchantID从DB删除Merchant实例
func (mdb *BackendMerchantDB) Delete(merchantID string) error {
	if _, ok := mdb.merchantStore[merchantID]; !ok {
		return fmt.Errorf("this merchant not exist:%s", merchantID)
	}
	delete(mdb.merchantStore, merchantID)
	return nil
}

// Create 将Merchant实例增加到DB
func (mdb *BackendMerchantDB) Create(merchant *Merchant) error {
	if _, ok := mdb.merchantStore[merchant.MerchantID]; ok {
		return fmt.Errorf("this merchant already exist:%s", merchant.MerchantID)
	}
	mdb.merchantStore[merchant.MerchantID] = merchant
	return nil
}

// Update 将Merchant实例更新到DB
func (mdb *BackendMerchantDB) Update(merchant *Merchant) error {
	if _, ok := mdb.merchantStore[merchant.MerchantID]; !ok {
		return fmt.Errorf("this merchant not exist:%s", merchant.MerchantID)
	}
	mdb.merchantStore[merchant.MerchantID] = merchant
	return nil
}

// BackendTokenDB 实现TokenDB接口的后端数据库，仅示意
type BackendTokenDB struct {
	tokenStore map[string]*Token // key:accessToken, value:*Token
}

// NewBackendTokenDB 生成BackendTokenDB实例
func NewBackendTokenDB() *BackendTokenDB {
	return &BackendTokenDB{map[string]*Token{}}
}

// CreateToken 创建Token实例
func (tdb *BackendTokenDB) CreateToken(appID string, appSecret string) (*Token, error) {
	token := &Token{
		AppID:            appID,
		AppSecret:        appSecret,
		Scope:            fmt.Sprintf("Scope-%s", appID),
		AccessToken:      RandomToken(),
		AccessCreateAt:   time.Now(),
		AccessExpiresIn:  TokenExpiry,
		RefreshToken:     RandomToken(),
		RefreshCreateAt:  time.Now(),
		RefreshExpiresIn: RefreshExpiry,
	}
	tdb.tokenStore[token.AccessToken] = token
	return token, nil
}

// DeleteToken 从DB删除accessToken对应的Token实例
func (tdb *BackendTokenDB) DeleteToken(accessToken string) error {
	if _, ok := tdb.tokenStore[accessToken]; !ok {
		return fmt.Errorf("this accessToken not exist:%s", accessToken)
	}
	delete(tdb.tokenStore, accessToken)
	return nil
}

// GetToken 从DB获取accessToken对应的Token实例
func (tdb *BackendTokenDB) GetToken(accessToken string) (*Token, error) {
	if _, ok := tdb.tokenStore[accessToken]; !ok {
		return nil, fmt.Errorf("this accessToken not exist:%s", accessToken)
	}
	return tdb.tokenStore[accessToken], nil
}

// VerifyToken 通过DB验证accessToken是否有效
func (tdb *BackendTokenDB) VerifyToken(accessToken string) error {
	token, err := tdb.GetToken(accessToken)
	if err != nil {
		return err
	}
	// 判断accessToken是否过期。创建时间+生存期>当前时间 则表示已经过期。
	if token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Before(time.Now()) {
		return fmt.Errorf("accessToken expires. accessToken=%s", accessToken)
	}
	return nil
}

// RefreshToken 对accessToken进行刷新，延长其有效期
func (tdb *BackendTokenDB) RefreshToken(accessToken string) (string, error) {
	token, err := tdb.GetToken(accessToken)
	if err != nil {
		return "", err
	}
	// 判断accessToken是否过期。创建时间+生存期<当前时间 则过期。
	if token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Before(time.Now()) {
		// accessToken 已经过期则不再续期
		return "", fmt.Errorf("accessToken expires. accessToken=%s", accessToken)
	}
	// 判断refreshtoken是否过期。创建时间+生存期<当前时间 则过期。
	if token.GetRefreshCreateAt().Add(token.GetRefreshExpiresIn()).Before(time.Now()) {
		// refreshtoken 已经过期则不再续期
		return "", fmt.Errorf("refreshtoken expires. accessToken=%s", accessToken)
	}
	// 生成新的accessToken
	token.SetAccessToken(RandomToken())
	token.SetAccessCreateAt(time.Now())
	token.SetAccessExpiresIn(TokenExpiry)
	tdb.tokenStore[token.GetAccessToken()] = token
	// 删除老的生成新的accessToken
	if err = tdb.DeleteToken(accessToken); err != nil {
		return "", err
	}
	return token.GetAccessToken(), nil
}

// RandomToken 生成一个随机的accessToken，仅测试用
func RandomToken() string {
	randStr := funk.RandomString(64)
	rand.Seed(time.Now().UnixNano())

	randSubStr := []string{}
	for i := 0; i < len(randStr); i++ {
		randIdx := rand.Uint32() % 64
		randSubStr = append(randSubStr, string(randStr[randIdx]))
	}
	return strings.Join(randSubStr, "")
}
