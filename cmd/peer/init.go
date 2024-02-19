package peer

import (
	"fmt"
	"github.com/spf13/cobra"
	"hlf-easy/config"
	"hlf-easy/node"
)

type peerInitCmd struct {
	peerOpts config.PeerInitOptions
}

func (c peerInitCmd) validate() error {
	if c.peerOpts.ID == "" {
		return fmt.Errorf("--id is required")
	}
	if c.peerOpts.Local {
		if c.peerOpts.CAName == "" {
			return fmt.Errorf("--ca-name is required")
		}
	} else {
		// validate that the options are not empty
		if c.peerOpts.CAUrl == "" {
			return fmt.Errorf("--ca-url is required")
		}
		if !c.peerOpts.CAInsecure && c.peerOpts.CACert == "" {
			return fmt.Errorf("--ca-cert is required")
		}
		if c.peerOpts.EnrollID == "" {
			return fmt.Errorf("--enroll-id is required")
		}
		if c.peerOpts.EnrollSecret == "" {
			return fmt.Errorf("--enroll-secret is required")
		}
	}
	return nil
}

func (c peerInitCmd) run() error {
	err := node.EnrollPeerCertificates(c.peerOpts)
	if err != nil {
		return err
	}
	return nil
}

func newPeerInitCommand() *cobra.Command {
	c := peerInitCmd{
		peerOpts: config.PeerInitOptions{},
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
	f.BoolVar(&c.peerOpts.Local, "local", false, "Local provisioning")
	f.StringVar(&c.peerOpts.CAName, "ca-name", "", "Name of the CA")
	f.StringSliceVar(&c.peerOpts.Hosts, "hosts", []string{}, "Hosts")
	f.StringVar(&c.peerOpts.ID, "id", "", "ID of the peer")
	f.StringVar(&c.peerOpts.CAUrl, "ca-url", "", "URL of the CA")
	f.BoolVar(&c.peerOpts.CAInsecure, "ca-insecure", false, "CA certificate is not verified")
	f.StringVar(&c.peerOpts.CACert, "ca-cert", "", "Path to the CA tls certificate")
	f.StringVar(&c.peerOpts.EnrollID, "enroll-id", "", "Enroll ID")
	f.StringVar(&c.peerOpts.EnrollSecret, "enroll-secret", "", "Enroll secret")

	return cmd
}
