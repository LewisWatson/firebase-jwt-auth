package fireauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/LewisWatson/firebase-jwt-auth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gopkg.in/jose.v1/jwt"
)

var _ = Describe("fireauth", func() {

	var (
		firebase TokenVerifier
		err      error
	)

	BeforeEach(func() {

		// creating a new fireauth instance involves an HTTP request so only do it once
		if firebase == nil {

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderCacheControl, "..., max-age=19008, ...")
				fmt.Fprintln(w, jsonKeys)
			}))
			defer ts.Close()

			firebase, err = New("exampleProject")
			Expect(err).ToNot(HaveOccurred())
		}
	})

	Describe("validate", func() {

		var (
			claims jwt.Claims
		)

		Context("invalid token", func() {

			BeforeEach(func() {
				_, claims, err = firebase.Verify("invalid token")
			})

			It("should throw ErrNotCompact error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(ErrNotCompact))
			})

			It("should return nil claims", func() {
				Expect(claims).To(BeNil())
			})
		})

	})

})
