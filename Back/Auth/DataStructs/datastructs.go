package datastructs

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

// Jwt
type Auth struct {
	AcessTTL    time.Duration
	RefreshTTL  time.Duration
	Secret      *rsa.PrivateKey
	PublicKey   *rsa.PublicKey
	SignMethod  jwt.SigningMethod
	Audience    []string
	ServiceName string
}
type Claims struct {
	Type   string `json:"type,omitempty"`
	Role   string `json:"role,omitempty"`
	Email  string `json:"email,omitempty"`
	UserID uint64 `json:"userid,omitempty"`

	*jwt.RegisteredClaims
}

// Database
type UserCrenditals struct {
	ID        uint64 `gorm:"primaryKey"`
	Name      string
	Login     string
	Role      string
	Password  string
	Email     string
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime:milli"`
}
type DataBase struct {
	DB *gorm.DB
}
