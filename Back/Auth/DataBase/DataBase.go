package DataBase

import (
	"errors"

	dats "github.com/INebotov/SP/Back/Auth/DataStructs"
	vl "github.com/INebotov/SP/Back/Auth/Validations"

	"github.com/go-redis/redis"
	"gorm.io/gorm"
)

type DataBase struct {
	DB    *gorm.DB
	Redis *redis.Client
}

// Database Actions
func (db *DataBase) GetUser(login string) (res dats.UserCrenditals, err error) {
	var tx *gorm.DB
	if vl.ValidateEmail(login) {
		tx = db.DB.Raw("SELECT * FROM user_crenditals WHERE email = ? LIMIT 1", login).Scan(&res)
	} else {
		tx = db.DB.Raw("SELECT * FROM user_crenditals WHERE login = ? LIMIT 1", login).Scan(&res)
	}
	if tx.RowsAffected == 0 {
		return dats.UserCrenditals{}, errors.New("no such user")
	}
	return res, nil
}
func (db *DataBase) GetUserById(id uint64) (res dats.UserCrenditals, err error) {
	tx := db.DB.First(&res, id)

	if tx.RowsAffected == 0 {
		return dats.UserCrenditals{}, errors.New("no such user")
	}

	return res, nil
}

func (db *DataBase) CheckUnical(user dats.UserCrenditals) bool {
	var eres, lres int
	var etx, ltx *gorm.DB
	etx = db.DB.Raw("SELECT COUNT(email) FROM user_crenditals WHERE email = ?", user.Email).Scan(&eres)
	ltx = db.DB.Raw("SELECT COUNT(login) FROM user_crenditals WHERE login = ?", user.Login).Scan(&lres)

	return lres == 0 && eres == 0 && etx.Error == nil && ltx.Error == nil
}

func (db *DataBase) Register(user *dats.UserCrenditals) error {
	tx := db.DB.Create(user)
	return tx.Error
}
