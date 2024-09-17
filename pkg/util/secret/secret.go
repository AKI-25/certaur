package secret

import (
	"context"
	"fmt"

	certsv1 "github.com/AKI-25/certaur/pkg/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"github.com/AKI-25/certaur/pkg/util/certificate"
)


func IsOwnerReference(cert *certsv1.Certificate, secret *corev1.Secret) bool {
	for _, owner := range secret.OwnerReferences {
		if owner.APIVersion == certsv1.GroupVersion.String() && owner.Kind == "Certificate" && owner.Name == cert.Name {
			return true
		}
	}
	return false
}

// create a secret for certificate and key storage
func CreateSecret(req ctrl.Request, Client client.Client, ctx context.Context, cert *certsv1.Certificate, secretName string, crt, key []byte) error {
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

	if err := Client.Create(ctx, secret); err != nil {
		return err
	}
	return nil
}

// update already available secret

func UpdateSecret(client client.Client, ctx context.Context, secret *corev1.Secret, cert, key []byte) error {
	secret.Data["tls.crt"] = cert
	secret.Data["tls.key"] = key

	return client.Update(ctx, secret)
}

func CheckOwnership(ctx context.Context, Client client.Client, cert *certsv1.Certificate) (corev1.SecretList, error) {
	var secretList, ownedSecrets corev1.SecretList
	err := Client.List(ctx, &secretList)
	if err != nil {
		return corev1.SecretList{}, err
	}
	for _, s := range secretList.Items {
		if IsOwnerReference(cert, &s) && s.Name != cert.Spec.SecretRef.Name {
			ownedSecrets.Items = append(ownedSecrets.Items, s)
		}
	}
	return ownedSecrets, nil
}

func DeleteSecrets(ctx context.Context, Client client.Client, secretList *corev1.SecretList) error {
	for _, secret := range secretList.Items {
		err := Client.Delete(ctx, &secret, &client.DeleteOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func EnsureSecretIntegrity(ctx context.Context, Client client.Client, cert *certsv1.Certificate, secret *corev1.Secret) error {
	// Generate TLS certificate

	certPEM, keyPEM, err := certificate.GenerateTLSCertificate(cert.Spec.DnsName, cert.Spec.Validity)
	if err != nil {
		return err
	}
	// Update the secret with the latest certificate and key
	err = UpdateSecret(Client, ctx, secret, certPEM, keyPEM)
	if err != nil {
		return err
	}
	return nil
}

func FindAndDeletePreviousSecrets(ctx context.Context, Client client.Client, cert *certsv1.Certificate) error {
	ownedSecrets, err := CheckOwnership(ctx, Client, cert)
	if err != nil {
		return err
	}

	if len(ownedSecrets.Items) != 0 {
		fmt.Println("Certificate already owns a secret")
		// delete previously owned secrets
		err := DeleteSecrets(ctx, Client, &ownedSecrets)
		if err != nil {
			return err
		}
	}
	return nil
}

func CheckSecretIntegrity(cert *certsv1.Certificate, secret *corev1.Secret) (bool, error) {
	parsedCert, err := certificate.ExtractCertData(*secret)
	if err != nil {
		return false, err
    }
	// Check if the Common Name matches the dnsName field in the Certificate CR
	if err := parsedCert.VerifyHostname(cert.Spec.DnsName); err != nil {
		return false, nil
	}

	// Check if the certificate expiration date matches the validity field in the Certificate CR
	ok, err := certificate.CheckCertValidity(parsedCert.NotBefore, parsedCert.NotAfter, cert.Spec.Validity)
	if err != nil {
		return false, err
	} else if !ok {
		return ok, err
	}

	privateKey, err := certificate.ExtractKeyData(*secret)
	if err!= nil {
        return false, err
    }

	ok, err = certificate.CheckCertKey(&parsedCert, &privateKey)
	if err != nil {
		return false, err
	} else if !ok {
		return ok, err
	}

	return ok, nil
}

// func displaySecrets(secretList *corev1.SecretList) []string {
// 	var secretNames []string
// 	for _, secret := range secretList.Items {
// 		secretNames = append(secretNames, secret.Name)
// 	}
// 	return secretNames
// }
