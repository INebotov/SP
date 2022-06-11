package DataStructs

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Jwt

type TockenPair struct {
	Acess   string
	Refresh string
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
	Password  []byte
	Email     string
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime:milli"`
}

// Router
type UserArrived struct {
	Login    string `json:"login"`
	Password []byte `json:"password"`
}
