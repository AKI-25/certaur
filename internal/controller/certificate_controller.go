/*
Copyright 2024 IsmailAbdelkefi.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	// "sigs.k8s.io/controller-runtime/pkg/predicate"

	certsv1 "github.com/AKI-25/certaur/api/v1"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/finalizers,verbs=update

func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.Log

	// Fetch the Certificate instance
	var cert certsv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if apierrors.IsNotFound(err) {
			l.Info("Certificate resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		l.Error(err, "Failed to get Certificate")
		return ctrl.Result{}, err
	}

	secretName := cert.Spec.SecretRef.Name

	// Check if the secret already exists
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{Name: secretName, Namespace: req.Namespace}
	err := r.Get(ctx, secretNamespacedName, secret)

	// If secret doesn't exist, generate a new TLS certificate and create the secret
	if apierrors.IsNotFound(err) {
		// check if the certificate has owned a secret and delete if found
		err := findAndDeletePreviousSecrets(ctx, r, &cert)
		if err != nil {
			l.Error(err, "failed to find and delete previous secrets")
			return ctrl.Result{}, err
		}

		l.Info("Secret not found, creating new secret", "SecretName", secretName)

		// Generate TLS certificate
		crtPEM, keyPEM, err := generateTLSCertificate(cert.Spec.DnsName, cert.Spec.Validity)
		if err != nil {
			l.Error(err, "failed to generate TLS certificate")
			return ctrl.Result{}, err
		}
		// Create a new secret
		err = createSecret(req, r, ctx, &cert, secretName, crtPEM, keyPEM)
		if err != nil {
			l.Error(err, "failed to create secret")
			return ctrl.Result{}, err
		}

		l.Info("Successfully created secret", "SecretName", secretName)
		return ctrl.Result{}, nil
	} else if err != nil {
		l.Error(err, "unable to fetch Secret")
		return ctrl.Result{}, err
	}
	ok, err := checkSecretIntegrity(&cert, secret)
	if err != nil {
		l.Error(err, "unable to check secret's integrity")
		return ctrl.Result{}, err
	}
	if !ok {
		l.Info("Secret's integrity has been compromised, updating the secret", "SecretName", secretName)
		err := ensureSecretIntegrity(ctx, r, &cert, secret)
		if err != nil {
			l.Error(err, "unable to restore secret's integrity")
			return ctrl.Result{}, err
		}
	} else {
		l.Info("Certificate and its corresponding secret are valid", "CertificateName", cert.Name, "SecretName", secretName)
	}
	

	return ctrl.Result{}, nil
}

func ensureSecretIntegrity(ctx context.Context, r *CertificateReconciler, cert *certsv1.Certificate, secret *corev1.Secret) error {
	// Generate TLS certificate
	certPEM, keyPEM, err := generateTLSCertificate(cert.Spec.DnsName, cert.Spec.Validity)
	if err != nil {
		return err
	}
	// Update the secret with the latest certificate and key
	err = updateSecret(r, ctx, secret, certPEM, keyPEM)
	if err != nil {
		return err
	}
	return nil
}

func checkSecretIntegrity(cert *certsv1.Certificate, secret *corev1.Secret) (bool, error) {
	// Extract the tls.crt field from the secret
	certData, exists := secret.Data["tls.crt"]
	if !exists {
		return false, errors.New("secret does not contain tls.crt field")
	}

	// Decode and parse the certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return false, errors.New("failed to decode PEM block containing the certificate")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Check if the Common Name matches the dnsName field in the Certificate CR
	if err := parsedCert.VerifyHostname(cert.Spec.DnsName); err != nil {
		return false, nil
	}

	// Check if the certificate expiration date matches the validity field in the Certificate CR
	ok, err := checkCertValidity(parsedCert.NotBefore, parsedCert.NotAfter, cert.Spec.Validity)
	if err != nil {
		return false, err
	} else if !ok {
		return ok, err
	}

	keyData, exists := secret.Data["tls.key"]
	if !exists {
		return false, errors.New("secret does not contain tls.key field")
	}

	block, _ = pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return false, fmt.Errorf("failed to parse private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse private key: %v", err)
	}

	ok, err = checkCertKey(parsedCert, privateKey)
	if err != nil {
		return false, err
	} else if !ok {
		return ok, err
	}

	return ok, nil
}

func checkCertKey(cert *x509.Certificate, privKey *rsa.PrivateKey) (bool, error) {
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("certificate does not contain an RSA public key")
	}

	// Compare the modulus of both keys
	return pubKey.N.Cmp(privKey.N) == 0, nil
}

func checkCertValidity(notBefore, notAfter time.Time, validity string) (bool, error) {
	// Calculate the expected expiration date based on the CR's validity field
	daysStr := strings.TrimSuffix(validity, "d")
	validityDays, err := strconv.Atoi(daysStr)
	if err != nil {
		return false, fmt.Errorf("invalid validity format in CR: %v", err)
	}

	expectedExpiration := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	// Check if the certificate's expiration date matches the expected expiration date
	if !notAfter.Equal(expectedExpiration) {
		return false, nil
	}
	return true, nil

}

func findAndDeletePreviousSecrets(ctx context.Context, r *CertificateReconciler, cert *certsv1.Certificate) error {
	ownedSecrets, err := checkOwnership(ctx, r, cert)
	if err != nil {
		return err
	}

	if len(ownedSecrets.Items) != 0 {
		fmt.Println("owned secrets", "Names", displaySecrets(&ownedSecrets))
		fmt.Println("Certificate already owns a secret")
		// delete previously owned secrets
		err := deleteSecrets(ctx, r, &ownedSecrets)
		if err != nil {
			return err
		}
	}
	return nil
}

func displaySecrets(secretList *corev1.SecretList) []string {
	var secretNames []string
	for _, secret := range secretList.Items {
		secretNames = append(secretNames, secret.Name)
	}
	return secretNames
}

func deleteSecrets(ctx context.Context, r *CertificateReconciler, secretList *corev1.SecretList) error {
	for _, secret := range secretList.Items {
		err := r.Delete(ctx, &secret, &client.DeleteOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func checkOwnership(ctx context.Context, r *CertificateReconciler, cert *certsv1.Certificate) (corev1.SecretList, error) {
	var secretList, ownedSecrets corev1.SecretList
	err := r.List(ctx, &secretList)
	if err != nil {
		return corev1.SecretList{}, err
	}
	for _, s := range secretList.Items {
		if isOwnerReference(cert, &s) && s.Name != cert.Spec.SecretRef.Name {
			ownedSecrets.Items = append(ownedSecrets.Items, s)
		}
	}
	return ownedSecrets, nil
}

// update already available secret

func updateSecret(r *CertificateReconciler, ctx context.Context, secret *corev1.Secret, cert, key []byte) error {
	secret.Data["tls.crt"] = cert
	secret.Data["tls.key"] = key

	return r.Client.Update(ctx, secret)
}

// generate a TLS certificate and key based on the provided DNS and validity
func generateTLSCertificate(dns string, validity string) ([]byte, []byte, error) {
	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	validityInt, err := extractDaysOfValidity(validity)
	if err != nil {
		return nil, nil, err
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		DNSNames:              []string{dns},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityInt),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Encode the certificate and key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM, nil
}

// get the numeric part of the validity of the certificate
func extractDaysOfValidity(val string) (int, error) {
	val = strings.TrimSuffix(val, "d")
	days, err := strconv.Atoi(val)
	if err != nil {
		return 0, err
	}
	return days, nil
}

// create a secret for certificate and key storage
func createSecret(req ctrl.Request, r *CertificateReconciler, ctx context.Context, cert *certsv1.Certificate, secretName string, crt, key []byte) error {
	secret := &corev1.Secret{
		ObjectMeta: ctrl.ObjectMeta{
			Name:      secretName,
			Namespace: req.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cert, certsv1.GroupVersion.WithKind("Certificate")),
			},
		},
		Data: map[string][]byte{
			"tls.crt": crt,
			"tls.key": key,
		},
		Type: corev1.SecretTypeTLS,
	}

	if err := r.Create(ctx, secret); err != nil {
		return err
	}
	return nil
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// pred := predicate.GenerationChangedPredicate{}
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1.Certificate{}).
		Owns(&corev1.Secret{}).
		// WithEventFilter(pred).
		Complete(r)
}

func isOwnerReference(cert *certsv1.Certificate, secret *corev1.Secret) bool {
	for _, owner := range secret.OwnerReferences {
		if owner.APIVersion == certsv1.GroupVersion.String() && owner.Kind == "Certificate" && owner.Name == cert.Name {
			return true
		}
	}
	return false
}
