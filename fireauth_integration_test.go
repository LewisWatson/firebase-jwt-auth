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

	// the token will not be valid, but the code should still be able to
	// retrieve the latest keys from firebase
	It("should return token verification error", func() {
		Expect(err.Error()).To(ContainSubstring("verification error"))
	})
})
