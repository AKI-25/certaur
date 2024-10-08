package webhook

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	certsv1 "github.com/AKI-25/certaur/pkg/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Context for making API requests

type Validator struct {
	client client.Client
	scheme *runtime.Scheme
}

var (
	dnsNameRegex  = `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$`
	validityRegex = `^\d+d$`
)

// log is for logging in this package.
var certificatelog = logf.Log.WithName("certificate-resource")

// +kubebuilder:webhook:path=/mutate-certs-k8c-io-v1-certificate,mutating=true,failurePolicy=fail,sideEffects=None,groups=certs.k8c.io,resources=certificates,verbs=create;update,versions=v1,name=mcertificate.kb.io,admissionReviewVersions=v1

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (v Validator) SetupWebhookWithManager(mgr ctrl.Manager) error {

	// instantiate a Validator
	certificateValidator := &Validator{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
	}

	// register the webhook with the manager.
	return ctrl.NewWebhookManagedBy(mgr).
		For(&certsv1.Certificate{}).
		WithValidator(certificateValidator).
		WithDefaulter(certificateValidator).
		Complete()
}

var _ admission.CustomDefaulter = &Validator{}

// +kubebuilder:webhook:path=/validate-certs-k8c-io-v1-certificate,mutating=false,failurePolicy=fail,sideEffects=None,groups=certs.k8c.io,resources=certificates,verbs=create;update,versions=v1,name=vcertificate.kb.io,admissionReviewVersions=v1

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (v *Validator) Default(ctx context.Context, obj runtime.Object) error {
	cert, ok := obj.(*certsv1.Certificate)
	if !ok {
		return fmt.Errorf("unexpected type: %T", obj)
	}

	certificatelog.Info("default", "name", cert.Name)

	v.defaultValidity(cert)
	v.defaultSecretName(cert)

	return nil
}

func (v *Validator) defaultValidity(cert *certsv1.Certificate) {
	if cert.Spec.Validity == "" {
		cert.Spec.Validity = "365d"
	}
}

func (v *Validator) defaultSecretName(cert *certsv1.Certificate) {
	if cert.Spec.SecretRef.Name == "" {
		cert.Spec.SecretRef.Name = fmt.Sprintf("%s-secret", cert.Name)
	}
}

// implement a custom validator

var _ admission.CustomValidator = &Validator{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (v *Validator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	var allErrs []string

	cert, ok := obj.(*certsv1.Certificate)
	if !ok {
		allErrs = append(allErrs, fmt.Sprintf("unexpected type: %T", obj))
	}
	certificatelog.Info("validate create", "name", cert.Name)

	if err := validateDNSName(cert); err != nil {
		allErrs = append(allErrs, err.Error())
	}
	if err := validateValidity(cert); err != nil {
		allErrs = append(allErrs, err.Error())
	}
	if err := validateSecretName(v.client, cert); err != nil {
		allErrs = append(allErrs, err.Error())
	}

	if len(allErrs) == 0 {
		return nil, nil
	}
	return allErrs, errors.New("failed to create resource")
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (v *Validator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	cert, ok := newObj.(*certsv1.Certificate)
	if !ok {
		return []string{
			fmt.Sprintf("unexpected type: %T", newObj),
		}, nil
	}

	certificatelog.Info("validate update", "name", cert.Name)

	return v.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (v *Validator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func validateDNSName(c *certsv1.Certificate) error {
	match, _ := regexp.MatchString(dnsNameRegex, c.Spec.DnsName)
	if !match {
		return field.Invalid(field.NewPath("spec").Child("dnsName"), c.Spec.DnsName, "invalid DNS name")
	}
	return nil
}

// checks that validity is in the correct format and range.
func validateValidity(c *certsv1.Certificate) error {
	match, _ := regexp.MatchString(validityRegex, c.Spec.Validity)
	if !match {
		return errors.New("invalid validity format, must be a positive integer followed by 'd'")
	}

	// Extract the integer part of validity and check the range (0 - 1825)
	daysStr := strings.TrimSuffix(c.Spec.Validity, "d")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 || days > 1825 {
		return errors.New("invalid validity format, validity must be between 1 and 1825 days")
	}

	return nil
}

func validateSecretName(client client.Client, c *certsv1.Certificate) error {
	ctx := context.Background()

	// check if the secret already exists
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{Name: c.Spec.SecretRef.Name, Namespace: c.Namespace}
	err := client.Get(ctx, secretNamespacedName, secret)
	if err == nil {
		return errors.New("secret already exists")
	}
	return nil
}

type Options webhook.Options

func SetupNewWebhookServer(opts Options) webhook.Server {
	return webhook.NewServer(webhook.Options(opts))
}
