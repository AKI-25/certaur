package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// generate a TLS certificate and key based on the provided DNS and validity
func GenerateTLSCertificate(dns string, validity string) ([]byte, []byte, error) {
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

func CheckCertValidity(notBefore, notAfter time.Time, validity string) (bool, error) {
	// Calculate the expected expiration date based on the CR's validity field
	daysStr := strings.TrimSuffix(validity, "d")
	validityDays, err := strconv.Atoi(daysStr)
	if err != nil {
		return false, fmt.Errorf("invalid validity format in CR: %v", err)
	}

	expectedExpiration := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	// Check if the certificate's expiration date matches the expected expiration date
	if !notAfter.Equal(expectedExpiration) {
		return false, nil
	}
	return true, nil

}

func CheckCertKey(cert *x509.Certificate, privKey *rsa.PrivateKey) (bool, error) {
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("certificate does not contain an RSA public key")
	}

	// Compare the modulus of both keys
	return pubKey.N.Cmp(privKey.N) == 0, nil
}

func ExtractCertData(secret corev1.Secret) (x509.Certificate, error) {
	// Extract the tls.crt field from the secret
	certData, exists := secret.Data["tls.crt"]
	if !exists {
		return x509.Certificate{}, errors.New("secret does not contain tls.crt field")
	}

	// Decode and parse the certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return x509.Certificate{}, errors.New("failed to decode PEM block containing the certificate")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return x509.Certificate{}, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return *parsedCert, nil
}

func ExtractKeyData(secret corev1.Secret) (rsa.PrivateKey, error) {
	keyData, exists := secret.Data["tls.key"]
	if !exists {
		return rsa.PrivateKey{}, errors.New("secret does not contain tls.key field")
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return rsa.PrivateKey{}, fmt.Errorf("failed to parse private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return rsa.PrivateKey{}, fmt.Errorf("failed to parse private key: %v", err)
	}

	return *privateKey, nil
}

func GeneratePrivateKeyPEM() ([]byte, error) {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Marshal the private key into PKCS#1 ASN.1 DER format
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// Encode the private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return privateKeyPEM, nil
}
