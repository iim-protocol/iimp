/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"github.com/spf13/cobra"
)

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from the IIMP server, clearing any stored session information.",
	Run: func(cmd *cobra.Command, args []string) {
		sessionExists, err := dbmodels.LoadIIMPSession()
		if err != nil {
			fmt.Printf("Error loading session: %v\n", err)
			return
		}
		if !sessionExists {
			fmt.Println("No active session found. You are already logged out.")
			return
		}

		iimpClient := iimp_go_client.NewIIMP(dbmodels.IIMPSession.ServerUrl)
		authorization := "Bearer " + dbmodels.IIMPSession.AccessToken
		result, err := iimpClient.Logout(cmd.Context(), iimp_go_client.LogoutRequest{
			Auth: iimp_go_client.LogoutRequestAuthParams{
				Authorization: &authorization,
			},
		})
		if err != nil {
			fmt.Printf("Error logging out: %v\n", err)
			return
		} else if result.StatusCode != 204 {
			fmt.Printf("Logout failed with status code: %d\n", result.StatusCode)
			return
		} else {
			err := dbmodels.ClearSessionFile()
			if err != nil {
				fmt.Printf("Error clearing session file: %v\n", err)
				return
			}
			fmt.Println("Logout successful.")
		}
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// logoutCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// logoutCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
