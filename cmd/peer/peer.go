package peer

import (
	"embed"
	"github.com/spf13/cobra"
	"hlf-easy/cmd/peer/anchorpeers"
	"io"
)

func NewPeerCmd(out io.Writer, errOut io.Writer, views embed.FS) *cobra.Command {
	cmd := &cobra.Command{
		Use: "peer",
	}
	cmd.AddCommand(
		newPeerInitCommand(),
		newPeerStartCommand(views),
		newPeerJoinCommand(),
		anchorpeers.NewAnchorPeersCmd(out, errOut),
	)
	return cmd
}
