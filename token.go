package authtoken

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

// Claims returns the tokens claims as type jwt.MapClaims
func Claims(tok *jwt.Token) jwt.MapClaims {
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return jwt.MapClaims{}
	}
	return claims
}

// Token a jwt token; If token string is valid returns valid token and nil.
func (a *Auth) Token(tokenString string) (*jwt.Token, error) {
	tok, err := jwt.Parse(tokenString, a.keyFunc)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token not valid")
	}
	return tok, nil
}

// NewToken generates a new jwt token
func (a *Auth) NewToken(claims jwt.MapClaims) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	return token.SignedString(a.secret)
}
