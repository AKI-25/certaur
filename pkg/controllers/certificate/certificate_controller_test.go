package controller

import (
	"context"
	"fmt"
	"testing"

	certsv1 "github.com/AKI-25/certaur/pkg/api/v1"
	certificateutil "github.com/AKI-25/certaur/pkg/util/certificate"
	secretutil "github.com/AKI-25/certaur/pkg/util/secret"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	. "github.com/onsi/ginkgo/v2"
)

var ctx context.Context

var (
	testCertName   = "test-cert"
	testSecretName = "test-secret"
)

func TestCertificateController(t *testing.T) {
	// Set up the reconciler
	scheme := runtime.NewScheme()
	_ = certsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true))
	recorder := &FakeRecorder{}
	reconciler := &CertificateReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Logger:   logger,
		Recorder: recorder,
	}
	t.Run("Secret Creation", func(t *testing.T) {
		// Create a sample Certificate CR
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testCertName,
				Namespace: "default",
			},
			Spec: certsv1.CertificateSpec{
				SecretRef: certsv1.SecretReference{Name: testSecretName},
				DnsName:   "test.example.com",
				Validity:  "365d",
			},
		}

		// Add the Certificate resource to the fake client
		err := fakeClient.Create(context.TODO(), cert)
		assert.NoError(t, err)

		// Simulate the Reconcile function
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      testCertName,
				Namespace: "default",
			},
		}
		result, err := reconciler.Reconcile(context.TODO(), req)

		// Assertions
		assert.NoError(t, err)
		assert.False(t, result.Requeue)

		// Check if the secret was created
		secret := &corev1.Secret{}
		err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: testSecretName, Namespace: "default"}, secret)
		assert.NoError(t, err)
		assert.Equal(t, testSecretName, secret.Name)
		assert.Contains(t, secret.Data, "tls.crt")
		assert.Contains(t, secret.Data, "tls.key")

		// Verify events were recorded
		assert.Contains(t, recorder.Events, "SecretCreationSuccessful")

		err = secretutil.EnsureSecretIntegrity(ctx, reconciler.Client, cert, secret)
		assert.NoError(t, err)

		// Clean up after test
		t.Cleanup(func() {
			_ = fakeClient.Delete(ctx, cert)
		})
	})

	t.Run("Secret Tamper", func(t *testing.T) {
		// Create a sample Certificate CR
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testCertName,
				Namespace: "default",
			},
			Spec: certsv1.CertificateSpec{
				SecretRef: certsv1.SecretReference{Name: testSecretName},
				DnsName:   "test.example.com",
				Validity:  "365d",
			},
		}

		// Add the Certificate resource to the fake client
		err := fakeClient.Create(context.TODO(), cert)
		assert.NoError(t, err)

		// Step 2: Trigger the first reconcile to create the Secret
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      testCertName,
				Namespace: "default",
			},
		}
		_, err = reconciler.Reconcile(context.TODO(), req)
		assert.NoError(t, err)

		// Fetch the created Secret
		secret := &corev1.Secret{}
		err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: testSecretName, Namespace: "default"}, secret)
		assert.NoError(t, err)

		// Step 3: Tamper with the Secret (replace with a valid but incorrect private key)
		tamperedKeyPEM, err := certificateutil.GeneratePrivateKeyPEM()
		assert.NoError(t, err)

		secret.Data["tls.key"] = tamperedKeyPEM
		err = fakeClient.Update(context.TODO(), secret)
		assert.NoError(t, err)

		// Step 4: Simulate Reconcile after tampering
		_, err = reconciler.Reconcile(context.TODO(), req)
		assert.NoError(t, err)

		// Step 5: Check if the Secret was fixed (restored to valid data)
		fixedSecret := &corev1.Secret{}
		err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: testSecretName, Namespace: "default"}, fixedSecret)
		assert.NoError(t, err)

		err = secretutil.EnsureSecretIntegrity(ctx, reconciler.Client, cert, fixedSecret)
		assert.NoError(t, err)

		// Verify that events were recorded for tampered detection and fix
		assert.Contains(t, recorder.Events, "SecretIntegrityCheckFailed")
		assert.Contains(t, recorder.Events, "SecretIntegrityRestored")

		// Cleanup after test
		t.Cleanup(func() {
			_ = fakeClient.Delete(ctx, cert)
		})
	})

	t.Run("Secret Deletion", func(t *testing.T) {
		// Create a sample Certificate CR
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testCertName,
				Namespace: "default",
			},
			Spec: certsv1.CertificateSpec{
				SecretRef: certsv1.SecretReference{Name: testSecretName},
				DnsName:   "test.example.com",
				Validity:  "365d",
			},
		}

		// Add the Certificate resource to the fake client
		err := fakeClient.Create(context.TODO(), cert)
		assert.NoError(t, err)

		// Trigger the first reconcile to create the Secret
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      testCertName,
				Namespace: "default",
			},
		}
		_, err = reconciler.Reconcile(context.TODO(), req)
		assert.NoError(t, err)

		assert.Contains(t, recorder.Events, "SecretCreationSuccessful")

		// Empty the recorder event list
		recorder.Events = []string{}

		// Fetch the created Secret
		secret := &corev1.Secret{}
		err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: testSecretName, Namespace: "default"}, secret)
		assert.NoError(t, err)

		// Delete the Secret
		err = fakeClient.Delete(context.TODO(), secret)
		assert.NoError(t, err)

		// Trigger the second reconcile to remidiate for the deletion of the secret
		_, err = reconciler.Reconcile(context.TODO(), req)
		assert.NoError(t, err)

		fmt.Println(recorder.Events)
		assert.Contains(t, recorder.Events, "SecretCreationSuccessful")

		// Clean up after test
		t.Cleanup(func() {
			_ = fakeClient.Delete(ctx, cert)
		})
	})
}

type FakeRecorder struct {
	Events []string
}

func (r *FakeRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	r.Events = append(r.Events, reason)
}

func (r *FakeRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	r.Events = append(r.Events, reason)
}

func (r *FakeRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	r.Events = append(r.Events, reason)
}
