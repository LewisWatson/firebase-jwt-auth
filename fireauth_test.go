package fireauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/benbjohnson/clock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

var _ = Describe("fireauth", func() {

	var (
		firebase  *FireAuth
		mockClock *clock.Mock
		err       error
	)

	BeforeEach(func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(HeaderCacheControl, "..., max-age=19008, ...")
			fmt.Fprintln(w, jsonKeys)
		}))
		defer ts.Close()

		mockClock = clock.NewMock()
		mockClock.Set(time.Date(2016, time.February, 02, 8, 0, 0, 0, time.UTC))

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
			userID string
			claims jwt.Claims
		)

		Context("valid token", func() {

			BeforeEach(func() {

				claimTimeOverride := &claimTimeOverride{
					exp: time.Now().Unix() + 1000,
					iat: mockClock.Now().Unix() - 1000,
				}
				firebase.setClaimTimeOverride(claimTimeOverride)

				userID, claims, err = firebase.Verify(token)
			})

			It("should not thow an error", func() {
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return correct user ID", func() {
				Expect(userID).To(Equal("TE19E2gU2aUxZP4t02mLW3VCMF63"))
			})

			It("should return 9 claims", func() {
				Expect(len(claims)).To(Equal(9))
			})

		})

		Context("token not signed by active keys", func() {

			BeforeEach(func() {

				claimTimeOverride := &claimTimeOverride{
					exp: time.Now().Unix() + 1000,
					iat: mockClock.Now().Unix() - 1000,
				}
				firebase.setClaimTimeOverride(claimTimeOverride)

				_, _, err = firebase.Verify(token2)
			})

			It("should not thow an error", func() {
				Expect(err).To(Equal(ErrRSAVerification))
			})

		})

		Context("expired token", func() {

			BeforeEach(func() {
				claimTimeOverride := &claimTimeOverride{
					exp: time.Now().Unix() - 1000,
					iat: mockClock.Now().Unix() - 1000,
				}
				firebase.setClaimTimeOverride(claimTimeOverride)

				_, _, err = firebase.Verify(token)
			})

			It("should thow a token is expired error", func() {
				Expect(err).To(Equal(jwt.ErrTokenIsExpired))
			})

		})

		Context("token not yet issued", func() {

			BeforeEach(func() {
				claimTimeOverride := &claimTimeOverride{
					exp: time.Now().Unix() + 1000,
					iat: mockClock.Now().Unix() + 1000,
				}
				firebase.setClaimTimeOverride(claimTimeOverride)

				_, _, err = firebase.Verify(token)
			})

			It("should thow a token not issued yet error", func() {
				Expect(err).To(Equal(ErrNotIssuedYet))
			})

		})

		Context("invalid token", func() {

			BeforeEach(func() {
				_, claims, err = firebase.Verify("invalid token")
			})

			It("should throw ErrNotCompact error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(jws.ErrNotCompact))
			})

			It("should return nil claims", func() {
				Expect(claims).To(BeNil())
			})
		})

	})

	Describe("update stale keys", func() {

		BeforeEach(func() {

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderCacheControl, "..., max-age=1337, ...")
				fmt.Fprintln(w, jsonKeys2)
			}))
			defer ts.Close()
			firebase.KeyURL = ts.URL

			mockClock.Set(time.Date(2017, time.February, 02, 8, 0, 0, 0, time.UTC))

			firebase.Verify(token)
		})

		Specify("max-age should now be 1337", func() {
			maxAge := firebase.keyExpire - mockClock.Now().Unix()
			Expect(maxAge).To(Equal(int64(1337)))
		})

		Specify("Firebase should now have 2 keys", func() {
			Expect(len(firebase.publicKeys)).To(Equal(2))
		})

	})

	Describe("non stale keys don't need updated", func() {

		BeforeEach(func() {

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderCacheControl, "..., max-age=1337, ...")
				fmt.Fprintln(w, jsonKeys2)
			}))
			defer ts.Close()
			firebase.KeyURL = ts.URL

			mockClock.Set(time.Date(2016, time.February, 02, 8, 0, 0, 0, time.UTC))

			firebase.Verify(token)
		})

		Specify("max-age should still be 19008", func() {
			maxAge := firebase.keyExpire - mockClock.Now().Unix()
			Expect(maxAge).To(Equal(int64(19008)))
		})

		Specify("Firebase should still have 4 keys", func() {
			Expect(len(firebase.publicKeys)).To(Equal(4))
		})

	})

})
