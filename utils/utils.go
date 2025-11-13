package utils

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/device"
)

func GetLogger(iface string, verbose bool) *device.Logger {
	return device.NewLogger(
		GetLogLevel(verbose),
		fmt.Sprintf("(%s) ", iface),
	)
}

func GetLogLevel(verbose bool) int {
	if verbose {
		return device.LogLevelVerbose
	}
	switch os.Getenv("LOG_LEVEL") {
	case "verbose", "debug":
		return device.LogLevelVerbose
	case "error":
		return device.LogLevelError
	case "silent":
		return device.LogLevelSilent
	}
	return device.LogLevelError
}
