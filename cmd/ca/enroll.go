package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"hlf-easy/certs"
	"hlf-easy/utils"
	"io"
	"net"
	"os"
)

type enrollCmd struct {
	Name       string
	Local      bool
	Type       string
	CommonName string
	TLS        bool
	Hosts      []string
	Output     string
}

func (c *enrollCmd) validate() error {
	if c.Name == "" {
		return errors.Errorf("--name is required")
	}
	if c.Type == "" {
		return errors.Errorf("--type is required")
	}
	if c.CommonName == "" {
		return errors.Errorf("--common-name is required")
	}
	return nil
}
func (c *enrollCmd) run(out io.Writer, errOut io.Writer) error {
	caConfig, err := utils.GetCAConfig(c.Name)
	if err != nil {
		return err
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
	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey
	if c.TLS {
		caCert = caConfig.TLSCACert
		caKey = caConfig.TLSCAKey
	} else {
		caCert = caConfig.CACert
		caKey = caConfig.CAKey
	}
	// create client
	userCert, userKey, err := certs.GenerateCertificate(
		certs.GenerateCertificateOptions{
			CommonName:       c.CommonName,
			OrganizationUnit: []string{c.Type},
			IPAddresses:      ips,
			DNSNames:         dnsNames,
		},
		caCert,
		caKey,
	)
	if err != nil {
		return err
	}
	crtPem := utils.EncodeX509Certificate(userCert)
	pkPem, err := utils.EncodePrivateKey(userKey)
	if err != nil {
		return err
	}
	userYaml, err := yaml.Marshal(map[string]interface{}{
		"key": map[string]interface{}{
			"pem": string(pkPem),
		},
		"cert": map[string]interface{}{
			"pem": string(crtPem),
		},
	})
	if err != nil {
		return err
	}
	if c.Output != "" {
		err = os.WriteFile(c.Output, userYaml, 0644)
		if err != nil {
			return err
		}
	} else {
		_, err = io.Copy(out, bytes.NewReader(userYaml))
		if err != nil {
			return err
		}
	}

	return nil
}
func newCAEnrollCommand(out io.Writer, errOut io.Writer) *cobra.Command {
	c := &enrollCmd{}
	cmd := &cobra.Command{
		Use: "enroll",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(out, errOut)
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.Name, "name", "", "Name of the CA")
	f.BoolVar(&c.Local, "local", false, "Enroll a local CA")
	f.StringVar(&c.Type, "type", "", "Type of the user to be crated")
	f.StringVar(&c.CommonName, "common-name", "", "Common name of the user")
	f.StringSliceVar(&c.Hosts, "hosts", []string{}, "Hosts")
	f.BoolVar(&c.TLS, "tls", false, "Use TLS CA")
	f.StringVarP(&c.Output, "output", "o", "", "Output file")
	return cmd
}
