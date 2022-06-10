package configuration

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"gopkg.in/yaml.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func (c *Config) Configure(file string, a *Auth, db *DataBase, r *Router) {
	// Reading Config File
	body, err := os.ReadFile(file)
	CheckPanic(err)
	err = yaml.Unmarshal(body, &c)
	CheckPanic(err)

	// TODO: Checking
	// Creating DB
	db.DB, err = gorm.Open(postgres.Open(fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=%s",
		c.Database.Postgres.Host, c.Database.Postgres.User, c.Database.Postgres.Password, c.Database.Postgres.DB,
		c.Database.Postgres.Port, c.Database.Postgres.Sslmode, c.Database.Postgres.TimeZone)), &gorm.Config{})
	CheckPanic(err)
	err = db.DB.AutoMigrate(UserCrenditals{})
	CheckPanic(err)
	// Configuring  Auth Services TTL
	a.AcessTTL = time.Duration(c.Jwt.AcsessTTL * uint64(time.Minute))
	a.RefreshTTL = time.Duration(c.Jwt.RefreshTTL * uint64(time.Hour))

	// Configurin Auth Secrets
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

	// Configuring Auth Env
	a.ServiceName = c.ServiceName
	a.Audience = c.Jwt.Audience

	// Configuring Router
	r.Port = c.Router.Port
}
