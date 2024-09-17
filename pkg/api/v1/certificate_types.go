package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateSpec defines the desired state of Certificate
type CertificateSpec struct {
	// DNS specifies the DNS name for the certificate
	DnsName string `json:"dnsName,omitempty"`
	// Validity specifies for how many days the certificate is valid
	Validity string `json:"validity,omitempty"`
	// SecretRef refers to the secret in which the certificate is stored
	SecretRef SecretReference `json:"secretRef,omitempty"`
}

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

// CertificateList contains a list of Certificate
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Certificate{}, &CertificateList{})
}
