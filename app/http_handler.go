package app

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func Auth(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		errLogger.Println("The structure of the body is wrong:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get user from db
	user := User{}
	err = userCollection.FindOne(context.TODO(), bson.M{"guid": credentials.GUID}).Decode(&user)
	if err != nil {
		errLogger.Println("Error in finding user by GUID:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	accessTokenString, accessExpirationTime, err := GenerateToken(credentials.GUID, 5*time.Minute)
	if err != nil {
		errLogger.Println("There is an error in creating the JWT:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshTokenString, refreshExpirationTime, err := GenerateToken(credentials.GUID, 30*24*time.Hour)
	if err != nil {
		errLogger.Println("There is an error in creating the JWT:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	hashedToken, err := GetHash(refreshTokenString)
	if err != nil {
		errLogger.Println("There is an error in creating bcrypt hash:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	refreshTokenString = base64.StdEncoding.EncodeToString([]byte(refreshTokenString))

	_, err = userCollection.UpdateOne(context.TODO(), bson.M{"guid": credentials.GUID}, bson.M{"$set": bson.M{"refresh_token": hashedToken}})
	if err != nil {
		errLogger.Println("There is an error in updating db:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessTokenString,
		Expires:  accessExpirationTime,
		HttpOnly: true,
		Secure:   true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		Expires:  refreshExpirationTime,
		HttpOnly: true,
		Secure:   true,
	})
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	accessC, err := r.Cookie("access_token")
	refreshC, err1 := r.Cookie("refresh_token")
	if err != nil || err1 != nil {
		if errors.Is(err, http.ErrNoCookie) || errors.Is(err1, http.ErrNoCookie) {
			errLogger.Println("No cookies recieved:", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	accessTokenStr, refreshTokenStr := accessC.Value, refreshC.Value
	claims := Claims{}
	accessToken, err := jwt.ParseWithClaims(accessTokenStr, &claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !accessToken.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Get user from db and check refresh token
	user := User{}
	err = userCollection.FindOne(context.TODO(), bson.M{"guid": claims.GUID}).Decode(&user)
	if err != nil {
		errLogger.Println("Error in finding user by GUID:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	refreshToken, err := base64.StdEncoding.DecodeString(refreshTokenStr)
	checkSum := sha512.Sum512(refreshToken)
	err = bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), checkSum[:])
	if err != nil {
		errLogger.Println("Wrong refresh token:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create refresh and access tokens
	accessTokenString, accessExpirationTime, err := GenerateToken(claims.GUID, 5*time.Minute)
	if err != nil {
		errLogger.Println("There is an error in creating the JWT:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshTokenString, refreshExpirationTime, err := GenerateToken(claims.GUID, 30*24*time.Hour)
	if err != nil {
		errLogger.Println("There is an error in creating the JWT:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	hashedToken, err := GetHash(refreshTokenString)
	if err != nil {
		errLogger.Println("There is an error in creating bcrypt hash:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	refreshTokenString = base64.StdEncoding.EncodeToString([]byte(refreshTokenString))

	_, err = userCollection.UpdateOne(context.TODO(), bson.M{"guid": user.GUID}, bson.M{"$set": bson.M{"refresh_token": hashedToken}})
	if err != nil {
		errLogger.Println("There is an error in updating db:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessTokenString,
		Expires:  accessExpirationTime,
		HttpOnly: true,
		Secure:   true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		Expires:  refreshExpirationTime,
		HttpOnly: true,
		Secure:   true,
	})
}
