package authtoken

import (
	"errors"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// Parse a jwt token
func (j *Auth) Parse(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, j.keyFunc)
}

// GetToken finds, parses and validates token in the request header with
// matching the key provided.
// returns an error is the token is not valid.
func (j *Auth) GetToken(key string, r *http.Request) (*jwt.Token, error) {
	tokenString := r.Header.Get(key)
	return j.IsValid(tokenString)
}

// GetClaims returns the tokens claims as type jwt.MapClaims
func GetClaims(tok *jwt.Token) jwt.MapClaims {
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return jwt.MapClaims{}
	}
	return claims
}

// IsValid a jwt token; If token string is valid returns valid token and nil.
func (j *Auth) IsValid(tokenString string) (*jwt.Token, error) {
	tok, err := j.Parse(tokenString)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token not valid")
	}

	return tok, nil
}

// GenerateToken generates a new jwt token
func (j *Auth) GenerateToken(claims jwt.MapClaims) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	return token.SignedString(j.secret)
}
