package anchorpeers

import (
	"github.com/spf13/cobra"
	"io"
)

func NewAnchorPeersCmd(out io.Writer, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use: "anchorpeers",
	}
	cmd.AddCommand(
		newAnchorPeersSetCommand(),
	)
	return cmd
}
