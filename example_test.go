package fireauth_test

import (
	"io/ioutil"
	"log"

	"github.com/LewisWatson/firebase-jwt-auth"
)

func ExampleVerify() {

	fireauth, err := fireauth.New("example project")
	if err != nil {
		log.Fatalf("%v", err)
	}

	token, err := getToken()
	if err != nil {
		log.Fatalf("%v", err)
	}

	userID, claims, err := fireauth.Verify(token)
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Printf("userID %v, claims %+v", userID, claims)
}

func getToken() (string, error) {
	content, err := ioutil.ReadFile("testdata/token.txt")
	if err != nil {
		return "", err
	}

	return string(content), nil
}
