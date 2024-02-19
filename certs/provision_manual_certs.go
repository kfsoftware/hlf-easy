package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"hlf-easy/utils"
	"math/big"
	"net"
	"time"
)

type GenerateCertificateOptions struct {
	CommonName       string
	OrganizationUnit []string
	IPAddresses      []net.IP
	DNSNames         []string
}

func GenerateCertificate(
	o GenerateCertificateOptions,
	parsedCaCert *x509.Certificate,
	parsedCaKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		SubjectKeyId: computeSKI(priv),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		Subject: pkix.Name{
			OrganizationalUnit: o.OrganizationUnit,
			CommonName:         o.CommonName,
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		DNSNames:              o.DNSNames,
		IPAddresses:           o.IPAddresses,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parsedCaCert, priv.Public(), parsedCaKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	newCert, err := utils.ParseX509Certificate(certPEM)
	if err != nil {
		return nil, nil, err
	}
	return newCert, priv, nil
}

func computeSKI(privKey *ecdsa.PrivateKey) []byte {
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)
	hash := sha256.Sum256(raw)
	return hash[:]
}
