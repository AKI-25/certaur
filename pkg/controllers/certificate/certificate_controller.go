package controller

import (
	"context"
	"fmt"

	certsv1 "github.com/AKI-25/certaur/pkg/api/v1"
	certificateutil "github.com/AKI-25/certaur/pkg/util/certificate"
	secretutil "github.com/AKI-25/certaur/pkg/util/secret"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Logger   logr.Logger
	Recorder record.EventRecorder
}

func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Fetch the Certificate instance
	var cert certsv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if apierrors.IsNotFound(err) {
			r.RecordAndLogInfo(&cert, "CertificateCreationFailed", "Certificate resource not found.")
			// r.Logger.Info("Certificate resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		r.Logger.Error(err, "Failed to get Certificate")
		return ctrl.Result{}, err
	}

	secretName := cert.Spec.SecretRef.Name

	// Check if the secret already exists
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{Name: secretName, Namespace: req.Namespace}
	err := r.Get(ctx, secretNamespacedName, secret)

	// If secret doesn't exist, generate a new TLS certificate and create the secret
	if apierrors.IsNotFound(err) {
		// clean up orphaned Kubernetes secrets that are still owned by a Certificate Custom Resource (CR)
		// but are no longer actively associated with it,
		// likely due to an interruption during the reconciliation process.
		err := secretutil.FindAndDeletePreviousSecrets(ctx, r.Client, &cert)
		if err != nil {
			r.Logger.Error(err, "failed to find and delete previous secrets")
			return ctrl.Result{}, err
		}

		r.Logger.Info("Secret not found, creating new secret", "SecretName", secretName)

		// Generate TLS certificate
		crtPEM, keyPEM, err := certificateutil.GenerateTLSCertificate(cert.Spec.DnsName, cert.Spec.Validity)
		if err != nil {
			r.Logger.Error(err, "failed to generate TLS certificate")
			return ctrl.Result{}, err
		}

		// Create a new secret
		err = secretutil.CreateSecret(req, r.Client, ctx, &cert, secretName, crtPEM, keyPEM)
		if err != nil {
			r.RecordAndLogError(&cert, "SecretCreationFailed", fmt.Sprintf("Failed to create Secret %s: %v", cert.Spec.SecretRef.Name, err), err)
			return ctrl.Result{}, err
		}

		r.RecordAndLogInfo(&cert, "SecretCreationSuccessful", fmt.Sprintf("Successfully created Secret %s", cert.Spec.SecretRef.Name))
		return ctrl.Result{}, nil
	} else if err != nil {
		r.Logger.Error(err, "unable to fetch Secret")
		return ctrl.Result{}, err
	}
	ok, err := secretutil.CheckSecretIntegrity(&cert, secret)
	if err != nil {
		r.Logger.Error(err, "unable to check secret's integrity")
		return ctrl.Result{}, err
	}
	if !ok {
		r.RecordAndLogInfo(&cert, "SecretIntegrityCheckFailed", fmt.Sprintf("Secret's integrity has been compromised: Secret %s", cert.Spec.SecretRef.Name))
		err := secretutil.EnsureSecretIntegrity(ctx, r.Client, &cert, secret)
		if err != nil {
			r.RecordAndLogError(&cert, "SecretIntegrityRestoreFailed", "unable to restore secret's integrity", err)
			return ctrl.Result{
				Requeue: true,
			}, err
		}
		r.RecordAndLogError(&cert, "SecretIntegrityRestored", "secret's integrity is restored", err)
	} else {
		r.RecordAndLogInfo(&cert, "CertificateValid", fmt.Sprintf("Certificate %s and its corresponding secret %s are valid", cert.Name, secretName))
		r.Logger.Info("Certificate and its corresponding secret are valid", "CertificateName", cert.Name, "SecretName", secretName)
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

func (r *CertificateReconciler) RecordAndLogInfo(cert *certsv1.Certificate, message, reason string) {
	r.Logger.Info(message, "Reason", reason)
	r.Recorder.Event(cert, corev1.EventTypeNormal, message, reason)
}

func (r *CertificateReconciler) RecordAndLogError(cert *certsv1.Certificate, message, reason string, err error) {
	r.Logger.Error(err, message)
	r.Recorder.Event(cert, corev1.EventTypeWarning, message, reason)
}
