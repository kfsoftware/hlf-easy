package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"hlf-easy/config"
	"hlf-easy/utils"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type initCmd struct {
	Organization       string
	Country            string
	Locality           string
	OrganizationalUnit string
	StreetAddress      string
	Name               string
	Hosts              []string
}

func (c *initCmd) run() error {
	tlsCert, tlsPK, err := c.createDefaultTLSCert()
	if err != nil {
		return err
	}
	_ = tlsPK
	logrus.Infof("tlsCert: %s", utils.EncodeX509Certificate(tlsCert))

	caCert, caPK, err := c.createDefaultCA("ca")
	if err != nil {
		return err
	}
	_ = caPK
	logrus.Infof("caCert: %s", utils.EncodeX509Certificate(caCert))

	tlsCACert, tlsCAPK, err := c.createDefaultCA("tlsca")
	if err != nil {
		return err
	}
	_ = tlsCAPK
	logrus.Infof("tlsCACert: %s", utils.EncodeX509Certificate(tlsCACert))

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	dirPath := filepath.Join(
		homeDir,
		fmt.Sprintf("hlf-easy/cas/%s", c.Name),
	)
	err = os.MkdirAll(dirPath, 0755) // Creates the directory if it doesn't exist
	if err != nil {
		return err
	}
	tlsKeyBytes, err := utils.EncodePrivateKey(tlsPK)
	if err != nil {
		return err
	}
	caKeyBytes, err := utils.EncodePrivateKey(caPK)
	if err != nil {
		return err
	}
	tlsCAKeyBytes, err := utils.EncodePrivateKey(tlsCAPK)
	if err != nil {
		return err
	}
	caConfig := config.CAConfig{
		CaCert:    utils.EncodeX509Certificate(caCert),
		CaKey:     caKeyBytes,
		CaName:    c.Name,
		TlsCACert: utils.EncodeX509Certificate(tlsCACert),
		TlsCAKey:  tlsCAKeyBytes,
		TlsCert:   utils.EncodeX509Certificate(tlsCert),
		TlsKey:    tlsKeyBytes,
	}
	filePath := filepath.Join(dirPath, "config.json")
	configBytes, err := json.MarshalIndent(caConfig, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filePath, configBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (c *initCmd) validate() error {
	if len(c.Hosts) == 0 {
		return errors.Errorf("--hosts must be specified")
	}
	if c.Name == "" {
		return errors.Errorf("--name must be specified")
	}

	return nil
}

func (c *initCmd) createDefaultTLSCert() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.Fatalf("Failed to generate serial number: %v", err)
		return nil, nil, err
	}
	var ips []net.IP
	var dnsNames []string
	for _, host := range c.Hosts {
		// check if it's ip address
		ip := net.ParseIP(host)
		if ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	x509Cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{c.Organization},
			Country:            []string{c.Country},
			Locality:           []string{c.Locality},
			OrganizationalUnit: []string{c.OrganizationalUnit},
			StreetAddress:      []string{c.StreetAddress},
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          computeSKI(caPrivKey),
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, x509Cert, x509Cert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return crt, caPrivKey, nil
}

// compute Subject Key Identifier
func computeSKI(privKey *ecdsa.PrivateKey) []byte {
	// Marshall the public key
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Hash it
	hash := sha256.Sum256(raw)
	return hash[:]
}
func (c *initCmd) createDefaultCA(commonName string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.Fatalf("Failed to generate serial number: %v", err)
		return nil, nil, err
	}
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	signCA := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{c.Organization},
			Country:            []string{c.Country},
			Locality:           []string{c.Locality},
			OrganizationalUnit: []string{c.OrganizationalUnit},
			StreetAddress:      []string{c.StreetAddress},
			CommonName:         commonName,
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		SubjectKeyId:          computeSKI(caPrivKey),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, signCA, signCA, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return crt, caPrivKey, nil
}

func newCAInitCommand() *cobra.Command {
	c := initCmd{}
	cmd := &cobra.Command{
		Use: "init",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.Name, "name", "", "Name")
	f.StringVar(&c.Organization, "organization", "Kung Fu Software", "Organization")
	f.StringVar(&c.Country, "country", "ES", "Country")
	f.StringVar(&c.Locality, "locality", "Alicante", "Locality")
	f.StringVar(&c.OrganizationalUnit, "organizational-unit", "Tech", "OrganizationalUnit")
	f.StringVar(&c.StreetAddress, "street-address", "Alicante", "StreetAddress")
	f.StringSliceVar(&c.Hosts, "hosts", []string{}, "Hosts")

	return cmd
}
