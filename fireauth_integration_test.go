// +build integration

package fireauth

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("fireauth integration test", func() {

	var (
		firebase *FireAuth
		err      error
	)

	BeforeEach(func() {
		firebase, err = New("example project")
		Expect(err).NotTo(HaveOccurred())
		_, _, err = firebase.Verify(token)
	})

	It("should return token is expired error", func() {
		Expect(err).To(Equal(ErrTokenExpired))
	})
})
