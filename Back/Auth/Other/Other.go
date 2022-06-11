package Other

import (
	"crypto/sha256"
	"errors"
)

// Hashing
func NewSHA256(data string) []byte {
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// Error Checking
func CompareErrors(errs ...error) error {
	str := ""
	for _, el := range errs {
		if el != nil {
			str += el.Error() + "\n"
		}
	}
	if str == "" {
		return nil
	}
	return errors.New(str[:len(str)-2])
}
