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
type CertificateStatus struct {}

// Certificate is the Schema for the certificates API
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

// CertificateList contains a list of Certificate
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Certificate{}, &CertificateList{})
}
