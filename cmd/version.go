package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of the program",
	Args:  cobra.ExactArgs(0),
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Println("Command-line client for HitVPN-Linux")
	fmt.Println("")
	fmt.Printf("HitVPN-Linux for %s-%s.\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("Information available at \"https://hitvpn.app\".")
	fmt.Println("Copyright (C) HitVPN <@hitvpnhelp>.")
}
