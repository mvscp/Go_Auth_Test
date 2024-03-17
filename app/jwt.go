package app

import (
	"crypto/sha512"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var jwtKey = []byte("my_secret_key")
var cost = 10

func GetHash(token string) (hashedToken string, err error) {
	checkSum := sha512.Sum512([]byte(token))
	hash, err := bcrypt.GenerateFromPassword(checkSum[:], cost)
	return string(hash), err
}

func GenerateToken(guid string, duration time.Duration) (tokenString string, expirationTime time.Time, err error) {
	expirationTime = jwt.TimeFunc().Add(duration)
	claims := Claims{
		GUID: guid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.UnixMilli(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err = token.SignedString(jwtKey)
	return tokenString, expirationTime, err
}
