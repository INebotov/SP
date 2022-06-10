package jwtengine

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func (a Auth) GenerateAcsess(user UserCrenditals) string {
	uuid, err := uuid.NewRandom()
	CheckSimple(err)
	if err != nil {
		return ""
	}
	now := time.Now().UTC()
	tk := &Claims{RegisteredClaims: &jwt.RegisteredClaims{
		Issuer: "JN Auth Server 0.0.0", Subject: user.Login,
		Audience:  a.Audience,
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
