package database

import (
	"errors"

	"gorm.io/gorm"
)

// Database Actions
func (db *DataBase) GetUser(login string) (res UserCrenditals, err error) {
	var tx *gorm.DB
	if ValidEmail(login) {
		tx = db.DB.Raw("SELECT * FROM user_crenditals WHERE email = ?", login).Scan(&res)
	} else {
		tx = db.DB.Raw("SELECT * FROM user_crenditals WHERE login = ?", login).Scan(&res)
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
func (db *DataBase) CompareUserPassword(userarrived UserArrived) (uint64, bool) {
	res := []struct {
		Id       uint64
		Password string
	}{}
	var tx *gorm.DB
	if ValidEmail(userarrived.Login) {
		tx = db.DB.Raw("SELECT id, password FROM user_crenditals WHERE email = ?", userarrived.Login).Scan(&res)
	} else {
		tx = db.DB.Raw("SELECT id, password FROM user_crenditals WHERE login = ?", userarrived.Login).Scan(&res)
	}
	if tx.RowsAffected == 0 {
		return 0, false
	}
	passhash := NewSHA256(userarrived.Password)
	for _, el := range res {
		if el.Password == passhash {
			return el.Id, true
		}
	}
	return 0, false
}
