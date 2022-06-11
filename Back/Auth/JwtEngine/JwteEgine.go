package JwtEngine

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	datb "github.com/INebotov/SP/Back/Auth/DataBase"
	dats "github.com/INebotov/SP/Back/Auth/DataStructs"
	other "github.com/INebotov/SP/Back/Auth/Other"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type Auth struct {
	AcessTTL    time.Duration
	RefreshTTL  time.Duration
	Secret      *rsa.PrivateKey
	Issuer      string
	PublicKey   *rsa.PublicKey
	SignMethod  jwt.SigningMethod
	Audience    []string
	ServiceName string
	datb.DataBase
}

func (a Auth) GenerateAcsess(user dats.UserCrenditals) (string, error) {
	uuid, err := uuid.NewRandom()
	now := time.Now().UTC()
	tk := &dats.Claims{RegisteredClaims: &jwt.RegisteredClaims{
		Issuer: a.Issuer, Subject: user.Login,
		Audience:  a.Audience,
		ExpiresAt: jwt.NewNumericDate(now.Add(a.AcessTTL)), NotBefore: jwt.NewNumericDate(now),
		IssuedAt: jwt.NewNumericDate(now), ID: uuid.String()}, Role: user.Role, Type: "Acess",
		Email: user.Email, UserID: user.ID}

	token, err2 := jwt.NewWithClaims(jwt.SigningMethodRS256, tk).SignedString(a.Secret)
	return token, other.CompareErrors(err, err2)
}
func (a Auth) GenerateRefresh() (string, error) {
	uuid, err := uuid.NewRandom()
	now := time.Now().UTC()
	tocken := uuid.String()
	exp := now.Add(a.RefreshTTL).Format("2006-01-02 15:04:05")
	err1 := a.DataBase.Redis.Set(tocken, exp, a.RefreshTTL).Err()

	return tocken, other.CompareErrors(err, err1)
}
func (a Auth) DeleteRefresh(tk string) error {
	return a.DataBase.Redis.Del(tk).Err()
}
func (a Auth) GetKeyPair(user dats.UserCrenditals) (dats.TockenPair, error) {
	as, err := a.GenerateAcsess(user)
	re, err1 := a.GenerateRefresh()
	return dats.TockenPair{Acess: as, Refresh: re}, other.CompareErrors(err, err1)
}
func (a Auth) CheckAndRipp(tk string) (dats.Claims, error) {
	token, err := jwt.ParseWithClaims(tk, &dats.Claims{}, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return a.PublicKey, nil
	})
	result, ok := token.Claims.(*dats.Claims)
	if !ok || !token.Valid {
		return dats.Claims{}, errors.New("non valid result")
	}
	if time.Now().After(result.ExpiresAt.Time) {
		return dats.Claims{}, errors.New("expired tocken")
	}
	return *result, err
}
func (a Auth) CheckRefresh(tk string) (bool, error) {
	exp, err := a.DataBase.Redis.Get(tk).Result()
	if err != nil {
		return false, err
	}
	tieme, err1 := time.Parse("2006-01-02 15:04:05", exp)
	return time.Now().After(tieme) || err != nil, other.CompareErrors(err, err1)
}

// func (a Auth) GenFromRefesh(refresh string) (string, bool) {

// }
