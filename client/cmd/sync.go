/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/iim-protocol/iimp/client/utils"
	"github.com/spf13/cobra"
)

// syncCmd represents the sync command
var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync all events from the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return utils.SyncOnce(cmd.Context(), true)
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)
}
