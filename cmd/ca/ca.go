package ca

import (
	"github.com/spf13/cobra"
	"io"
)

func NewCACmd(out io.Writer, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use: "ca",
	}
	cmd.AddCommand(
		newCAInitCommand(),
		newCAStartCommand(),
		newCAInspectCommand(out, errOut),
		newCAEnrollCommand(out, errOut),
	)
	return cmd
}
