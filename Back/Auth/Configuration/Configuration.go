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
		Audience   []string
		Secret     string
		Issuer     string
		PublicKey  string
	}
	Router struct {
		Port uint
	}
}

func (c *Config) Configure(file string, a *ath.Auth, db *datb.DataBase, r *rout.Router) {
	// Reading Config File
	body, err := os.ReadFile(file)
	other.CheckPanic(err)
	err = yaml.Unmarshal(body, &c)
	other.CheckPanic(err)

	// TODO: Checking
	// Creating DB
	db.DB, err = gorm.Open(postgres.Open(fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=%s",
		c.Database.Postgres.Host, c.Database.Postgres.User, c.Database.Postgres.Password, c.Database.Postgres.DB,
		c.Database.Postgres.Port, c.Database.Postgres.Sslmode, c.Database.Postgres.TimeZone)), &gorm.Config{})
	other.CheckPanic(err)
	err = db.DB.AutoMigrate(dats.UserCrenditals{})
	other.CheckPanic(err)
	// Configuring  Auth Services TTL
	a.AcessTTL = time.Duration(c.Jwt.AcsessTTL * uint64(time.Minute))
	a.RefreshTTL = time.Duration(c.Jwt.RefreshTTL * uint64(time.Hour))

	// Configurin Auth Secrets
	sec, err := os.ReadFile(c.Jwt.Secret)
	other.CheckPanic(err)
	a.Secret, err = jwt.ParseRSAPrivateKeyFromPEM(sec)
	other.CheckPanic(err)
	pub, err := os.ReadFile(c.Jwt.PublicKey)
	other.CheckPanic(err)
	a.PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(pub)
	other.CheckPanic(err)
	a.SignMethod = jwt.GetSigningMethod(c.Jwt.SignMethod)
	a.ServiceName = c.ServiceName

	// Configuring Auth Env
	a.ServiceName = c.ServiceName
	a.Audience = c.Jwt.Audience

	// Configuring Router
	r.Port = c.Router.Port
	r.AuthToolkit = *a
	r.DataBaseToolKit = *db

	// Boulshirt

	db.DB.Create(&dats.UserCrenditals{
		Name: "Ivan", Login: "IIvan", Role: "Admin", Password: other.NewSHA256("ButterFly777"),
		Email: "ivannebotov@justnets.ru",
	})
}
