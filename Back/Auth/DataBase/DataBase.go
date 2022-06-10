package DataBase

import (
	"errors"

	dats "github.com/INebotov/SP/Back/Auth/DataStructs"
	other "github.com/INebotov/SP/Back/Auth/Other"
	"gorm.io/gorm"
)

type DataBase struct {
	DB *gorm.DB
}

// Database Actions
func (db *DataBase) GetUser(login string) (res dats.UserCrenditals, err error) {
	var tx *gorm.DB
	if other.ValidEmail(login) {
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
