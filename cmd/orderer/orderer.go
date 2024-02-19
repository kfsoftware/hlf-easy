package orderer

import (
	"embed"
	"github.com/spf13/cobra"
	"io"
)

func NewOrdererCmd(out io.Writer, errOut io.Writer, views embed.FS) *cobra.Command {
	cmd := &cobra.Command{
		Use: "orderer",
	}
	cmd.AddCommand(
		newOrdererStartCommand(views),
	)
	return cmd
}
