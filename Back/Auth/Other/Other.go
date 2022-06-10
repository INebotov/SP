package Other

import (
	"crypto/sha256"
	"fmt"
	"net/mail"
)

// Hashing
func NewSHA256(data string) []byte {
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

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