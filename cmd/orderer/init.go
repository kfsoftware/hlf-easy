package orderer

import (
	"fmt"
	"github.com/spf13/cobra"
	"hlf-easy/config"
	"hlf-easy/node"
)

type ordererInitCmd struct {
	ordererOpts config.OrdererInitOptions
}

func (c ordererInitCmd) validate() error {
	if c.ordererOpts.ID == "" {
		return fmt.Errorf("--id is required")
	}
	if c.ordererOpts.Local {
		if c.ordererOpts.CAName == "" {
			return fmt.Errorf("--ca-name is required")
		}
	} else {
		// validate that the options are not empty
		if c.ordererOpts.CAUrl == "" {
			return fmt.Errorf("--ca-url is required")
		}
		if !c.ordererOpts.CAInsecure && c.ordererOpts.CACert == "" {
			return fmt.Errorf("--ca-cert is required")
		}
		if c.ordererOpts.EnrollID == "" {
			return fmt.Errorf("--enroll-id is required")
		}
		if c.ordererOpts.EnrollSecret == "" {
			return fmt.Errorf("--enroll-secret is required")
		}
	}
	return nil
}

func (c ordererInitCmd) run() error {
	err := node.EnrollOrdererCertificates(c.ordererOpts)
	if err != nil {
		return err
	}
	return nil
}

func newOrdererInitCommand() *cobra.Command {
	c := ordererInitCmd{
		ordererOpts: config.OrdererInitOptions{},
	}
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
	f.BoolVar(&c.ordererOpts.Local, "local", false, "Local provisioning")
	f.StringVar(&c.ordererOpts.CAName, "ca-name", "", "Name of the CA")
	f.StringSliceVar(&c.ordererOpts.Hosts, "hosts", []string{}, "Hosts")
	f.StringVar(&c.ordererOpts.ID, "id", "", "ID of the orderer")
	f.StringVar(&c.ordererOpts.CAUrl, "ca-url", "", "URL of the CA")
	f.BoolVar(&c.ordererOpts.CAInsecure, "ca-insecure", false, "CA certificate is not verified")
	f.StringVar(&c.ordererOpts.CACert, "ca-cert", "", "Path to the CA tls certificate")
	f.StringVar(&c.ordererOpts.EnrollID, "enroll-id", "", "Enroll ID")
	f.StringVar(&c.ordererOpts.EnrollSecret, "enroll-secret", "", "Enroll secret")

	return cmd
}
