package fireauth_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/LewisWatson/firebase-jwt-auth"
	"github.com/benbjohnson/clock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gopkg.in/jose.v1/jwt"
)

var _ = Describe("fireauth", func() {

	var (
		firebase  TokenVerifier
		token     string
		mockClock *clock.Mock
		err       error
	)

	BeforeEach(func() {

		if token == "" {
			content, err := ioutil.ReadFile("testdata/token.txt")
			Expect(err).NotTo(HaveOccurred())
			token = string(content)
		}

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(HeaderCacheControl, "..., max-age=19008, ...")
			fmt.Fprintln(w, jsonKeys)
		}))
		defer ts.Close()

		mockClock = clock.NewMock()
		mockClock.Set(time.Date(2017, time.February, 02, 8, 0, 0, 0, time.UTC))

		fb := &FireAuth{
			ProjectID: "ridesharelogger",
			KeyURL:    ts.URL,
			IssPrefix: IssPrefix,
			Clock:     mockClock,
		}

		err = fb.UpdatePublicKeys()
		Expect(err).ToNot(HaveOccurred())

		firebase = fb
	})

	Describe("validate", func() {

		var (
			claims jwt.Claims
		)

		Context("valid token", func() {

			BeforeEach(func() {
				_, claims, err = firebase.Verify(token)
			})

			It("should not thow an error", func() {
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("expired token", func() {

			BeforeEach(func() {
				mockClock.Set(time.Date(2018, time.February, 02, 8, 0, 0, 0, time.UTC))
				_, claims, err = firebase.Verify(token)
			})

			It("should not thow an error", func() {
				Expect(err).ToNot(HaveOccurred())
			})

		})

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
