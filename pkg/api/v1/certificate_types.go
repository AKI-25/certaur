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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateSpec defines the desired state of Certificate
// +kubebuilder:object:generate=true
type CertificateSpec struct {
	// DNS specifies the DNS name for the certificate
	DnsName string `json:"dnsName,omitempty"`
	// Validity specifies for how many days the certificate is valid
	Validity string `json:"validity,omitempty"`
	// SecretRef refers to the secret in which the certificate is stored
	SecretRef SecretReference `json:"secretRef,omitempty"`
}

// +kubebuilder:object:generate=true
type SecretReference struct {
	// Name of the secret
	Name string `json:"name"`
}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct{}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Domain",type=string,JSONPath=`.spec.dnsName`,description="Domain Name registered in the certificate"
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.secretRef.name`,description="Name of the secret associated with the certificate"
// +kubebuilder:printcolumn:name="Validity",type=string,JSONPath=`.spec.validity`,description="Duration of the validity of the certificate"

// Certificate is the Schema for the certificates API
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:object:generate=true
// CertificateList contains a list of Certificate
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Certificate{}, &CertificateList{})
}
