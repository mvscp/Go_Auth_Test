package app

import (
	"github.com/golang-jwt/jwt"
)

type User struct {
	GUID         string `bson:"guid"`
	RefreshToken string `bson:"refresh_token"`
}

type Credentials struct {
	GUID string `json:"guid"`
}

// Claims will be encoded to a JWT.
type Claims struct {
	GUID string `json:"guid"`
	jwt.StandardClaims
}
