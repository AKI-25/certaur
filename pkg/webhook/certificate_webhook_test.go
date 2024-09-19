package webhook

import (
	"context"
	"testing"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	certsv1 "github.com/AKI-25/certaur/pkg/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"k8s.io/apimachinery/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	. "github.com/onsi/ginkgo/v2"
)

var (
	testCertName = "test-cert"
	testSecretName = "test-secret"
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

func TestCertificateWebhook(t *testing.T) {
	ctx := context.TODO()

	// Setup scheme and fake client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, certsv1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create a Validator with fake client
	v := Validator{
		client: fakeClient,
		scheme: scheme,
	}

	
	t.Run("should default validity and secret name", func(t *testing.T) {
		// Create a certificate without validity and secret name
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testCertName,
				Namespace: "default",
			},
			Spec: certsv1.CertificateSpec{
				DnsName: "test.example.com",
				SecretRef: certsv1.SecretReference{
					Name: "",
				},
				Validity: "",
			},
		}

		// Run the defaulting logic
		err := v.Default(ctx, cert)
		require.NoError(t, err)

		// Assert that defaults are set
		assert.Equal(t, "365d", cert.Spec.Validity)
		assert.Equal(t, fmt.Sprintf("%s-secret", cert.Name), cert.Spec.SecretRef.Name)
	})

	t.Run("should reject invalid DNS names", func(t *testing.T) {
		// Create a certificate with an invalid DNS name
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testCertName,
				Namespace: "default",
			},
			Spec: certsv1.CertificateSpec{
				DnsName:  "invalid_dns_name",
				SecretRef: certsv1.SecretReference{
					Name: testSecretName,
				},
				Validity: "365d",
			},
		}

		// Run the validation logic
		warnings, err := v.ValidateCreate(ctx, cert)
		assert.Error(t, err)
		fmt.Println(err)
		assert.Contains(t, warnings[0], "invalid DNS name")
	})

	t.Run("should reject invalid validity values", func(t *testing.T) {
		// Create a certificate with an invalid validity
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testCertName,
				Namespace: "default",
			},
			Spec: certsv1.CertificateSpec{
				DnsName:  "valid.example.com",
				Validity: "invalid_validity",
			},
		}

		// Run the validation logic
		warnings, err := v.ValidateCreate(ctx, cert)
		assert.Error(t, err)
		assert.Contains(t, warnings[0], "invalid validity format")
	})

	t.Run("should reject existing secret names", func(t *testing.T) {
		// Create a secret in the fake client
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-secret",
				Namespace: "default",
			},
		}
		err := fakeClient.Create(ctx, secret)
		require.NoError(t, err)

		// Create a certificate that refers to the existing secret
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testCertName,
				Namespace: "default",
			},
			Spec: certsv1.CertificateSpec{
				DnsName: "valid.example.com",
				SecretRef: certsv1.SecretReference{
					Name: "existing-secret",
				},
				Validity: "365d",
			},
		}

		// Run the validation logic
		warnings, err := v.ValidateCreate(ctx, cert)
		assert.Error(t, err)
		assert.Contains(t, warnings[0], "secret already exists")
	})

	t.Run("should accept valid certificate requests", func(t *testing.T) {
		// Create a valid certificate
		cert := &certsv1.Certificate{
		    ObjectMeta: metav1.ObjectMeta{
				Name:      testCertName,
                Namespace: "default",
            },
			Spec: certsv1.CertificateSpec{
				DnsName:  "valid.example.com",
				Validity: "365d",
				SecretRef: certsv1.SecretReference{
					Name: "new-secret",
				},
			},
		}

		// Run the validation logic
		_, err := v.ValidateCreate(ctx, cert)
		assert.NoError(t, err)
	})
}