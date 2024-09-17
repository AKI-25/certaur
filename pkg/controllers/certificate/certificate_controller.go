package controller

import (
	"context"

	certsv1 "github.com/AKI-25/certaur/pkg/api/v1"
	certificateutil "github.com/AKI-25/certaur/pkg/util/certificate"
	secretutil "github.com/AKI-25/certaur/pkg/util/secret"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

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
		err := secretutil.FindAndDeletePreviousSecrets(ctx, r.Client, &cert)
		if err != nil {
			l.Error(err, "failed to find and delete previous secrets")
			return ctrl.Result{}, err
		}

		l.Info("Secret not found, creating new secret", "SecretName", secretName)

		// Generate TLS certificate
		crtPEM, keyPEM, err := certificateutil.GenerateTLSCertificate(cert.Spec.DnsName, cert.Spec.Validity)
		if err != nil {
			l.Error(err, "failed to generate TLS certificate")
			return ctrl.Result{}, err
		}

		// Create a new secret
		err = secretutil.CreateSecret(req, r.Client, ctx, &cert, secretName, crtPEM, keyPEM)
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
	ok, err := secretutil.CheckSecretIntegrity(&cert, secret)
	if err != nil {
		l.Error(err, "unable to check secret's integrity")
		return ctrl.Result{}, err
	}
	if !ok {
		l.Info("Secret's integrity has been compromised, updating the secret", "SecretName", secretName)
		err := secretutil.EnsureSecretIntegrity(ctx, r.Client, &cert, secret)
		if err != nil {
			l.Error(err, "unable to restore secret's integrity")
			return ctrl.Result{}, err
		}
	} else {
		l.Info("Certificate and its corresponding secret are valid", "CertificateName", cert.Name, "SecretName", secretName)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1.Certificate{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
