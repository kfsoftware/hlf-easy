package cmd

import (
	"embed"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"hlf-easy/cmd/ca"
	"hlf-easy/cmd/orderer"
	"hlf-easy/cmd/peer"
)

const (
	hlfEasyDesc = ``
)

// NewCmdHLFEasy creates a new root command for hlf-easy
func NewCmdHLFEasy(views embed.FS) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "hlf-easy",
		Short:        "CLI to easily run Hyperledger Fabric on baremetal",
		Long:         hlfEasyDesc,
		SilenceUsage: true,
	}
	logrus.SetLevel(logrus.DebugLevel)
	cmd.AddCommand(
		ca.NewCACmd(cmd.OutOrStdout(), cmd.ErrOrStderr()),
		peer.NewPeerCmd(cmd.OutOrStdout(), cmd.ErrOrStderr(), views),
		orderer.NewOrdererCmd(cmd.OutOrStdout(), cmd.ErrOrStderr(), views),
	)
	return cmd
}
