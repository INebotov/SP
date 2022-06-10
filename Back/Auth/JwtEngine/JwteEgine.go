package JwtEngine

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

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
}

func (a Auth) GenerateAcsess(user dats.UserCrenditals) string {
	uuid, err := uuid.NewRandom()
	other.CheckSimple(err)
	if err != nil {
		return ""
	}
	now := time.Now().UTC()
	tk := &dats.Claims{RegisteredClaims: &jwt.RegisteredClaims{
		Issuer: a.Issuer, Subject: user.Login,
		Audience:  a.Audience,
		ExpiresAt: jwt.NewNumericDate(now.Add(a.AcessTTL)), NotBefore: jwt.NewNumericDate(now),
		IssuedAt: jwt.NewNumericDate(now), ID: uuid.String()}, Role: user.Role, Type: "Acess",
		Email: user.Email, UserID: user.ID}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, tk).SignedString(a.Secret)
	other.CheckSimple(err)
	if err != nil {
		return ""
	}
	return token
}

func (a Auth) GenerateRefresh(user dats.UserCrenditals) string {
	uuid, err := uuid.NewRandom()
	other.CheckSimple(err)
	if err != nil {
		return ""
	}
	now := time.Now().UTC()
	tk := &dats.RefreshClaims{RegisteredClaims: &jwt.RegisteredClaims{
		Issuer: a.Issuer, Subject: user.Login,
		Audience:  a.Audience,
		ExpiresAt: jwt.NewNumericDate(now.Add(a.AcessTTL)), NotBefore: jwt.NewNumericDate(now),
		IssuedAt: jwt.NewNumericDate(now), ID: uuid.String()}, Type: "Refresh", UserID: user.ID}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, tk).SignedString(a.Secret)
	other.CheckSimple(err)
	if err != nil {
		return ""
	}
	return token
}

func (a Auth) GetKeyPair(user dats.UserCrenditals) dats.TockenPair {
	return dats.TockenPair{Acess: a.GenerateAcsess(user), Refresh: a.GenerateRefresh(user)}
}

func (a Auth) CheckAndRipp(tk string) (dats.Claims, error) {
	token, err := jwt.ParseWithClaims(tk, &dats.Claims{}, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return a.PublicKey, nil
	})
	other.CheckSimple(err)
	if err != nil {
		return dats.Claims{}, errors.New("non valid tocken format")
	}
	result, ok := token.Claims.(*dats.Claims)
	if !ok || !token.Valid {
		return dats.Claims{}, errors.New("non valid result")
	}
	if time.Now().After(result.ExpiresAt.Time) {
		return dats.Claims{}, errors.New("expired tocken")
	}
	return *result, nil
}

func (a Auth) CheckAndRippRefresh(tk string) (dats.RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(tk, &dats.RefreshClaims{}, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return a.PublicKey, nil
	})
	other.CheckSimple(err)
	if err != nil {
		return dats.RefreshClaims{}, errors.New("non valid tocken format")
	}
	result, ok := token.Claims.(*dats.RefreshClaims)
	if !ok || !token.Valid {
		return dats.RefreshClaims{}, errors.New("non valid result")
	}
	if time.Now().After(result.ExpiresAt.Time) {
		return dats.RefreshClaims{}, errors.New("expired tocken")
	}
	return *result, nil
}

// func (a Auth) GenFromRefesh(refresh string) (string, bool) {

// }
