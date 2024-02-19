package ca

import (
	"bytes"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"hlf-easy/utils"
	"io"
)

type inspectCmd struct {
	Name string
}

func (c *inspectCmd) validate() error {
	if c.Name == "" {
		return errors.Errorf("--name is required")
	}
	return nil
}
func (c *inspectCmd) run(out io.Writer, errOut io.Writer) error {
	caConfig, err := utils.GetCAConfig(c.Name)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	dataToExport := map[string]interface{}{
		"tlsCACert": string(utils.EncodeX509Certificate(caConfig.TLSCACert)),
		"caCert":    string(utils.EncodeX509Certificate(caConfig.CACert)),
	}
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	err = encoder.Encode(dataToExport)
	if err != nil {
		return err
	}
	// write to out
	_, err = io.Copy(out, &buf)
	if err != nil {
		return err
	}
	return nil
}
func newCAInspectCommand(out io.Writer, errOut io.Writer) *cobra.Command {
	c := &inspectCmd{}
	cmd := &cobra.Command{
		Use: "inspect",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(out, errOut)
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.Name, "name", "", "Name of the CA")
	return cmd
}
