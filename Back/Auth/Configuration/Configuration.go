package Configuration

import (
	"fmt"
	"os"
	"time"

	datb "github.com/INebotov/SP/Back/Auth/DataBase"
	dats "github.com/INebotov/SP/Back/Auth/DataStructs"
	ath "github.com/INebotov/SP/Back/Auth/JwtEngine"
	other "github.com/INebotov/SP/Back/Auth/Other"
	rout "github.com/INebotov/SP/Back/Auth/Router"
	"github.com/go-redis/redis"
	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/yaml.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

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
			DB       int
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
		Audience   []string
		Secret     string
		Issuer     string
		PublicKey  string
	}
	Router struct {
		Port uint
	}
}

func (c *Config) GetConfiguration(file string) error {
	body, err1 := os.ReadFile(file)
	err2 := yaml.Unmarshal(body, c)
	return other.CompareErrors(err1, err2)
}

func (c *Config) InitMyDataBases(db *datb.DataBase) error {
	var err error
	// Postgres
	db.DB, err = gorm.Open(postgres.Open(fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=%s",
		c.Database.Postgres.Host, c.Database.Postgres.User, c.Database.Postgres.Password, c.Database.Postgres.DB,
		c.Database.Postgres.Port, c.Database.Postgres.Sslmode, c.Database.Postgres.TimeZone)), &gorm.Config{})
	err1 := db.DB.AutoMigrate(dats.UserCrenditals{})

	// Redis
	password, err2 := os.ReadFile(c.Database.Redis.Password) // TODO: Password Collaborting
	db.Redis = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", c.Database.Redis.Host, c.Database.Redis.Port),
		Password: string(password),
		DB:       c.Database.Redis.DB,
	})

	return other.CompareErrors(err, err1, err2)

}

func (c *Config) InitMyJwtEngine(a *ath.Auth) error {
	var err1, err2 error
	a.AcessTTL = time.Duration(c.Jwt.AcsessTTL * uint64(time.Minute)) // TODO: Configuring Like m h s
	a.RefreshTTL = time.Duration(c.Jwt.RefreshTTL * uint64(time.Hour))

	// Configurin Auth Secrets
	sec, err := os.ReadFile(c.Jwt.Secret)

	a.Secret, err1 = jwt.ParseRSAPrivateKeyFromPEM(sec)
	pub, err := os.ReadFile(c.Jwt.PublicKey)
	a.PublicKey, err2 = jwt.ParseRSAPublicKeyFromPEM(pub)
	a.SignMethod = jwt.GetSigningMethod(c.Jwt.SignMethod)
	a.ServiceName = c.ServiceName

	// Configuring Auth Env
	a.ServiceName = c.ServiceName
	a.Audience = c.Jwt.Audience

	return other.CompareErrors(err, err1, err2)
}

func (c *Config) InitMyRouter(r *rout.Router) error {
	r.Port = c.Router.Port
	return nil
}

func (c *Config) Configure(file string, a *ath.Auth, db *datb.DataBase, r *rout.Router) error {
	return other.CompareErrors(c.GetConfiguration(file), c.InitMyDataBases(db), c.InitMyJwtEngine(a), c.InitMyRouter(r))
}
