package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// HTTP Router's
type UserArrived struct {
	Login    string
	Password string
}
type Router struct {
}

func (r *Router) CreateRouter() {
}

// JWT Translition
type Auth struct {
	AcessTTL    time.Duration
	RefreshTTL  time.Duration
	Secret      *rsa.PrivateKey
	PublicKey   *rsa.PublicKey
	SignMethod  jwt.SigningMethod
	ServiceName string
}
type Claims struct {
	Type   string `json:"type,omitempty"`
	Role   string `json:"role,omitempty"`
	Email  string `json:"email,omitempty"`
	UserID uint64 `json:"userid,omitempty"`

	*jwt.RegisteredClaims
}

func (a Auth) GenerateAcsess(user UserCrenditals) string {
	uuid, err := uuid.NewRandom()
	CheckSimple(err)
	if err != nil {
		return ""
	}
	now := time.Now().UTC()
	tk := &Claims{RegisteredClaims: &jwt.RegisteredClaims{
		Issuer: "JN Auth Server 0.0.0", Subject: user.Login,
		Audience:  jwt.ClaimStrings{"*.justnets.ru", "*.devcomun.ru", "*.everynumber.ru"},
		ExpiresAt: jwt.NewNumericDate(now.Add(a.AcessTTL)), NotBefore: jwt.NewNumericDate(now),
		IssuedAt: jwt.NewNumericDate(now), ID: uuid.String()}, Role: user.Role, Type: "Acess",
		Email: user.Email, UserID: user.ID}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, tk).SignedString(a.Secret)
	CheckSimple(err)
	if err != nil {
		return ""
	}
	return token
}
func (a Auth) CheckAndRipp(tk string) (Claims, error) {
	token, err := jwt.ParseWithClaims(tk, &Claims{}, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return a.PublicKey, nil
	})
	CheckSimple(err)
	if err != nil {
		return Claims{}, errors.New("non valid tocken format")
	}
	result, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return Claims{}, errors.New("non valid result")
	}
	if time.Now().After(result.ExpiresAt.Time) {
		return Claims{}, errors.New("expired tocken")
	}
	return *result, nil
}

// func (a Auth) GenFromRefesh(refresh string) (string, bool) {

// }

// Hashing
func NewSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return string(hash[:])
}

// Database Actions
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

func (db *DataBase) GetUser(login string) (res UserCrenditals, err error) {
	var tx *gorm.DB
	if ValidEmail(login) {
		tx = db.DB.Raw("SELECT * FROM usercrenditals WHERE email = ?", login).Scan(&res)
	} else {
		tx = db.DB.Raw("SELECT * FROM usercrenditals WHERE login = ?", login).Scan(&res)
	}
	if tx.RowsAffected == 0 {
		return UserCrenditals{}, errors.New("no such user")
	}
	return res, nil
}
func (db *DataBase) GetUserById(id uint64) (res UserCrenditals, err error) {
	tx := db.DB.First(&res, id)

	if tx.RowsAffected == 0 {
		return UserCrenditals{}, errors.New("no such user")
	}
	return res, nil
}
func (db *DataBase) CompareUserPassword(userarrived UserArrived) bool {
	res := []UserCrenditals{}
	var tx *gorm.DB
	if ValidEmail(userarrived.Login) {
		tx = db.DB.Raw("SELECT id, password FROM usercrenditals WHERE email = ?", userarrived.Login).Scan(&res)
	} else {
		tx = db.DB.Raw("SELECT id, password FROM usercrenditals WHERE login = ?", userarrived.Login).Scan(&res)
	}
	if tx.RowsAffected == 0 {
		return false
	}
	passhash := NewSHA256(userarrived.Password)
	for _, el := range res {
		if el.Password == passhash {
			return true
		}
	}
	return false
}

// Configuration
type Config struct {
	ServiceName string
	Database    struct {
		Postgres struct {
			DB       string
			Sslmode  string
			Password string
			User     string
			Port     uint
			Host     string
			TimeZone string
		}
		Redis struct {
			DB       uint
			Host     string
			Port     uint
			Password string
		}
		Mongo struct {
			User     string
			Password string
		}
	}
	Logs struct {
		To     []string
		Format string
		Date   bool
	}
	Jwt struct {
		AcsessTTL  uint64
		RefreshTTL uint64
		SignMethod string
		Secret     string
		PublicKey  string
	}
}

func (c *Config) Configure(file string, a *Auth, db *DataBase) {
	body, err := os.ReadFile(file)
	CheckPanic(err)
	err = yaml.Unmarshal(body, &c)
	CheckPanic(err)
	// TODO: Checking
	db.DB, err = gorm.Open(postgres.Open(fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=%s",
		c.Database.Postgres.Host, c.Database.Postgres.User, c.Database.Postgres.Password, c.Database.Postgres.DB,
		c.Database.Postgres.Port, c.Database.Postgres.Sslmode, c.Database.Postgres.TimeZone)), &gorm.Config{})
	CheckPanic(err)
	a.AcessTTL = time.Duration(c.Jwt.AcsessTTL * uint64(time.Minute))
	a.RefreshTTL = time.Duration(c.Jwt.RefreshTTL * uint64(time.Hour))
	sec, err := os.ReadFile(c.Jwt.Secret)
	CheckPanic(err)
	a.Secret, err = jwt.ParseRSAPrivateKeyFromPEM(sec)
	CheckPanic(err)
	pub, err := os.ReadFile(c.Jwt.PublicKey)
	CheckPanic(err)
	a.PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(pub)
	CheckPanic(err)
	a.SignMethod = jwt.GetSigningMethod(c.Jwt.SignMethod)
	a.ServiceName = c.ServiceName
	CheckPanic(err)
	db.DB.AutoMigrate(UserCrenditals{})
}

// Other
func ValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// Error Checking
func CheckPanic(err error) {
	if err != nil {
		panic(err)
	}
}
func CheckSimple(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

// Main
func main() {
	c := Config{}
	a := Auth{}
	db := DataBase{}
	c.Configure("./config/config.yaml", &a, &db)
	user, err := db.GetUserById(1)
	CheckSimple(err)
	res, err := a.CheckAndRipp(a.GenerateAcsess(user))
	CheckSimple(err)
	fmt.Println(res.Email)
}
