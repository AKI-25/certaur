[![Go Report Card](https://goreportcard.com/badge/github.com/AKI-25/certaur)](https://goreportcard.com/report/github.com/AKI-25/certaur)
# Certaur

**Certaur** is a Kubernetes operator that automates the creation and management of TLS certificates. By defining a custom resource `Certificate`, this operator generates TLS certificates and stores them in Kubernetes secrets for use with applications.

## Features

- Automatically generates TLS certificates based on the `Certificate` custom resource definition (CRD).
- Stores the generated certificates securely in Kubernetes secrets.
- Detects changes in certificates and ensures that it is up to date.

## Installation

### Prerequisites

- A running Kubernetes cluster (version 1.16+).
- Kubernetes CLI (`kubectl`) installed and configured to communicate with the cluster.

### Deploy Certaur

1. Clone the Certaur repository:

   ```bash
   git clone https://github.com/AKI-25/certaur
   cd certaur
   ```

2. Install the Certaur CRDs and operator using `kubectl`:

   ```bash
   kubectl apply -f deploy/installer.yaml
   ```

3. Verify that the Certaur operator is running:

   ```bash
   kubectl get pods -n certaur-system
   ```

   You should see the Certaur operator pod running.

## Usage

### Create a Certificate

To create a TLS certificate, define a `Certificate` resource. Below is an example manifest:

```yaml
apiVersion: certs.k8c.io/v1
kind: Certificate
metadata:
  name: certificate-test
spec:
  dnsName: example.k8s.io
  validity: 360d
  secretRef:
    name: my-certificate-secret
```

1. Apply the certificate manifest:

   ```bash
   kubectl apply -f certificate.yaml
   ```

2. Once applied, Certaur will automatically generate a TLS certificate and store it in the specified secret.

   You can check the secret using:

   ```bash
   kubectl get secret my-certificate-secret
   ```

### Retrieving the Certificate

To retrieve the generated certificate:

```bash
kubectl get secret example-certificate-secret -o yaml
```

The secret will contain the TLS certificate and key.

## Custom Resource Definition (CRD)

Certaur introduces a custom resource `Certificate`. The primary fields in the CRD are:

- `dnsName`: The primary domain name for the certificate.
- `validity`: The validity of the certificate in days.
- `secretRef.name`: The name of the secret where the certificate and private key will be stored.

## Contributing

If you would like to contribute to Certaur, please open an issue or submit a pull request. Contributions are welcome!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or support, feel free to open an issue on the [GitHub repository](https://github.com/AKI-25/certaur/issues).