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
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certsv1 "github.com/AKI-25/certaur/api/v1"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/finalizers,verbs=update

func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("certificate", req.NamespacedName)

	// Fetch the Certificate instance
	var cert certsv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Certificate resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Certificate")
		return ctrl.Result{}, err
	}

	secretName := cert.Spec.SecretRef.Name

	// Check if the secret already exists
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{Name: secretName, Namespace: req.Namespace}
	err := r.Get(ctx, secretNamespacedName, secret)

	// If secret doesn't exist, generate a new TLS certificate and create the secret
	if apierrors.IsNotFound(err) {
		log.Info("Secret not found, generating new certificate", "SecretName", secretName)

		// Create a new secret
		err = createSecret(req, r, ctx, secretName)
		if err != nil {
			log.Error(err, "failed to create secret")
			return ctrl.Result{}, err
		}

		log.Info("Successfully created secret", "SecretName", secretName)
		return ctrl.Result{}, nil
	} else if err != nil {
		log.Error(err, "unable to fetch Secret")
		return ctrl.Result{}, err
	}

	// Generate TLS certificate
	certPEM, keyPEM, err := generateTLSCertificate(cert.Spec.DnsName, cert.Spec.Validity)
	if err != nil {
		log.Error(err, "failed to generate TLS certificate")
		return ctrl.Result{}, err
	}
	
	// if the secret is available
	// Update the secret with the latest certificate and key
    err = updateSecret(r, ctx, secret, keyPEM, certPEM)
    if err!= nil {
        log.Error(err, "failed to update secret")
        return ctrl.Result{}, err
    }

	return ctrl.Result{}, nil
}

// update already available secret 

func updateSecret(r *CertificateReconciler, ctx context.Context, secret *corev1.Secret, key, cert []byte) error {
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
func createSecret(req ctrl.Request, r *CertificateReconciler, ctx context.Context, secretName string) error {
	secret := &corev1.Secret{
		ObjectMeta: ctrl.ObjectMeta{
			Name:      secretName,
			Namespace: req.Namespace,
		},
		Type: corev1.SecretTypeTLS,
	}

	if err := r.Create(ctx, secret); err != nil {
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1.Certificate{}).
		Complete(r)
}
