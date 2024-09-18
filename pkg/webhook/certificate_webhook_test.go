package webhook

import (
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("Certificate Webhook", func() {

	Context("When creating Certificate under Defaulting Webhook", func() {
		It("Should fill in the default value if a required field is empty", func() {})
	})

	Context("When creating Certificate under Validating Webhook", func() {
		It("Should deny if a required field is empty", func() {})

		It("Should admit if all required fields are provided", func() {})
	})

})
