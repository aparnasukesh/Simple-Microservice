package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
)

var MySigninKey = []byte(os.Getenv("SECRET_KEY"))

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Super secret information")
}

func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Token")
		if tokenString == "" {
			http.Error(w, "No authorization token provided", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Invalid signing method")
			}

			aud := "billing.jwtgo.io"
			if !token.Claims.(jwt.MapClaims).VerifyAudience(aud, false) {
				return nil, fmt.Errorf("Invalid audience")
			}

			iss := "jwtgo.io"
			if !token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false) {
				return nil, fmt.Errorf("Invalid issuer")
			}

			return MySigninKey, nil
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if token.Valid {
			endpoint(w, r)
		} else {
			fmt.Fprintf(w, "No authorization token provided")
		}
	}
}

func handleRequest() {
	http.HandleFunc("/", homePage)
	http.Handle("/secret", isAuthorized(homePage))
	log.Fatal(http.ListenAndServe(":9001", nil))
}

func main() {
	fmt.Println("Server is running...")
	handleRequest()
}
