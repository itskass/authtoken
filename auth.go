package authtoken

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// Auth is a jwt authority
type Auth struct {
	secret  []byte
	keyFunc func(token *jwt.Token) (interface{}, error)
}

// NewAuth Create a new hmac jwt authority
func NewAuth(secret string) *Auth {
	return &Auth{
		secret: []byte(secret),
		keyFunc: func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return []byte(secret), nil
		},
	}
}
