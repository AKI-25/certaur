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
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
    dnsNameRegex  = `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$`
    validityRegex = `^\d+d$`
)

// log is for logging in this package.
var certificatelog = logf.Log.WithName("certificate-resource")

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *Certificate) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-certs-k8c-io-v1-certificate,mutating=true,failurePolicy=fail,sideEffects=None,groups=certs.k8c.io,resources=certificates,verbs=create;update,versions=v1,name=mcertificate.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &Certificate{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *Certificate) Default() {
	certificatelog.Info("default", "name", r.Name)

	r.defaultValidity()
	r.defaultSecretName()
}

func (r *Certificate) defaultValidity() {
	if r.Spec.Validity == "" {
		r.Spec.Validity = "365d"
	}
}

func (r *Certificate) defaultSecretName() {
	if r.Spec.SecretRef.Name == "" {
		r.Spec.SecretRef.Name = fmt.Sprintf("%s-secret", r.Name)
	}
}
// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-certs-k8c-io-v1-certificate,mutating=false,failurePolicy=fail,sideEffects=None,groups=certs.k8c.io,resources=certificates,verbs=create;update,versions=v1,name=vcertificate.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &Certificate{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Certificate) ValidateCreate() (admission.Warnings, error) {
	certificatelog.Info("validate create", "name", r.Name)

	var allErrs []string

    if err := r.validateDNSName(); err != nil {
        allErrs = append(allErrs, err.Error())
    }
    if err := r.validateValidity(); err != nil {
        allErrs = append(allErrs, err.Error())
    }

    if len(allErrs) == 0 {
        return nil, nil
    }
    return allErrs, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Certificate) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	certificatelog.Info("validate update", "name", r.Name)

	// TODO(user): fill in your validation logic upon object update.
	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Certificate) ValidateDelete() (admission.Warnings, error) {
	certificatelog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil, nil
}

func (r *Certificate) validateDNSName() error {
    match, _ := regexp.MatchString(dnsNameRegex, r.Spec.DnsName)
    if !match {
        return field.Invalid(field.NewPath("spec").Child("dnsName"), r.Spec.DnsName, "invalid DNS name")
    }
    return nil
}

// checks that validity is in the correct format and range.
func (r *Certificate) validateValidity() error {
    match, _ := regexp.MatchString(validityRegex, r.Spec.Validity)
    if !match {
        return errors.New("invalid format, must be a positive integer followed by 'd'")  
    }

    // Extract the integer part of validity and check the range (0 - 1825)
    daysStr := strings.TrimSuffix(r.Spec.Validity, "d")
    days, err := strconv.Atoi(daysStr)
    if err != nil || days < 1 || days > 1825 {
		return errors.New("validity must be between 1 and 1825 days")
    }

    return nil
}