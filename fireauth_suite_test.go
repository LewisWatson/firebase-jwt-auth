package fireauth

import (
	"io/ioutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

var (
	jsonKeys  string
	jsonKeys2 string
	token     string
	token2    string
)

func TestAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "fireauth test suite")
}

var _ = BeforeSuite(func() {
	content, err := ioutil.ReadFile("testdata/keys.json")
	Expect(err).NotTo(HaveOccurred())
	jsonKeys = string(content)

	content, err = ioutil.ReadFile("testdata/keys2.json")
	Expect(err).NotTo(HaveOccurred())
	jsonKeys2 = string(content)

	content, err = ioutil.ReadFile("testdata/token.txt")
	Expect(err).NotTo(HaveOccurred())
	token = string(content)

	content, err = ioutil.ReadFile("testdata/token2.txt")
	Expect(err).NotTo(HaveOccurred())
	token2 = string(content)
})
