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

package v1

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	// "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Context for making API requests

type validator struct {
	client client.Client
	scheme *runtime.Scheme
}

var (
	dnsNameRegex  = `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$`
	validityRegex = `^\d+d$`
)

// log is for logging in this package.
var certificatelog = logf.Log.WithName("certificate-resource")

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *Certificate) SetupWebhookWithManager(mgr ctrl.Manager) error {

	// instanciate a Validator
	certificateValidator := &validator{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
	}

	// register the webhook with the manager.
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithValidator(certificateValidator).
		WithDefaulter(certificateValidator).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-certs-k8c-io-v1-certificate,mutating=true,failurePolicy=fail,sideEffects=None,groups=certs.k8c.io,resources=certificates,verbs=create;update,versions=v1,name=mcertificate.kb.io,admissionReviewVersions=v1

var _ admission.CustomDefaulter = &validator{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (v *validator) Default(ctx context.Context, obj runtime.Object) error {
	cert, ok := obj.(*Certificate)
	if !ok {
		return fmt.Errorf("unexpected type: %T", obj)
	}

	certificatelog.Info("default", "name", cert.Name)

	v.defaultValidity(cert)
	v.defaultSecretName(cert)

	return nil
}

func (v *validator) defaultValidity(cert *Certificate) {
	if cert.Spec.Validity == "" {
		cert.Spec.Validity = "365d"
	}
}

func (v *validator) defaultSecretName(cert *Certificate) {
	if cert.Spec.SecretRef.Name == "" {
		cert.Spec.SecretRef.Name = fmt.Sprintf("%s-secret", cert.Name)
	}
}

// +kubebuilder:webhook:path=/validate-certs-k8c-io-v1-certificate,mutating=false,failurePolicy=fail,sideEffects=None,groups=certs.k8c.io,resources=certificates,verbs=create;update,versions=v1,name=vcertificate.kb.io,admissionReviewVersions=v1

// implement a custom validator

var _ admission.CustomValidator = &validator{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (v *validator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	var allErrs []string

	cert, ok := obj.(*Certificate)
	if !ok {
		allErrs = append(allErrs, fmt.Sprintf("unexpected type: %T", obj))
	}
	certificatelog.Info("validate create", "name", cert.Name)

	if err := cert.validateDNSName(); err != nil {
		allErrs = append(allErrs, err.Error())
	}
	if err := cert.validateValidity(); err != nil {
		allErrs = append(allErrs, err.Error())
	}
	if err := cert.validateSecretName(v.client); err != nil {
		allErrs = append(allErrs, err.Error())
	}

	if len(allErrs) == 0 {
		return nil, nil
	}
	return allErrs, errors.New("failed to create resource")
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (v *validator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	cert, ok := newObj.(*Certificate)
	if !ok {
		return []string{
			fmt.Sprintf("unexpected type: %T", newObj),
		}, nil
	}

	certificatelog.Info("validate update", "name", cert.Name)

	v.ValidateCreate(ctx, newObj)
	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (v *validator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (c *Certificate) validateDNSName() error {
	match, _ := regexp.MatchString(dnsNameRegex, c.Spec.DnsName)
	if !match {
		return field.Invalid(field.NewPath("spec").Child("dnsName"), c.Spec.DnsName, "invalid DNS name")
	}
	return nil
}

// checks that validity is in the correct format and range.
func (c *Certificate) validateValidity() error {
	match, _ := regexp.MatchString(validityRegex, c.Spec.Validity)
	if !match {
		return errors.New("invalid format, must be a positive integer followed by 'd'")
	}

	// Extract the integer part of validity and check the range (0 - 1825)
	daysStr := strings.TrimSuffix(c.Spec.Validity, "d")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 || days > 1825 {
		return errors.New("validity must be between 1 and 1825 days")
	}

	return nil
}

func (c *Certificate) validateSecretName(client client.Client) error {
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
