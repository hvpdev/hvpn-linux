package cmd

import (
	"github.com/hvpdev/hvpn-linux/cmd/connect"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hvpn-linux",
	Short: "HitVPN-Linux command-line client",
	Long:  "A command-line client for managing HitVPN-Linux VPN connections",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(connect.ConnectCmd)
}
