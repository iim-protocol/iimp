/*
Copyright © 2026 Naman B Gor <devnamangor@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/iim-protocol/iimp/client/utils"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "iimp-client",
	Short: "A terminal ui client for iimp server",
	Long:  `iimp-client is a terminal user interface (TUI) client for the iimp server. It provides a user-friendly interface to interact with the iimp server, allowing users to use an iimp-server for instant messaging. This client implements the whole of IIMP and is compatible with any IIMP compatible server.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "signup" || cmd.Name() == "login" {
			return nil
		}

		// check if session exists
		sessionExists, err := dbmodels.LoadIIMPSession()
		if err != nil {
			return err
		}
		if !sessionExists {
			return fmt.Errorf("no active session found. Please login first.")
		}

		// refresh if necessary
		tokenExpiry, err := time.Parse(time.RFC3339, dbmodels.IIMPSession.AccessTokenExpiry)
		if err != nil {
			return err
		}
		if time.Now().Add(5 * time.Minute).After(tokenExpiry) { // add a buffer of 5 minutes before expiry
			iimpClient := iimp_go_client.NewIIMP(dbmodels.IIMPSession.ServerUrl)
			result, err := iimpClient.RefreshSession(cmd.Context(), iimp_go_client.RefreshSessionRequest{
				Body: iimp_go_client.RefreshSessionRequestBody{
					RefreshToken: dbmodels.IIMPSession.RefreshToken,
				},
			})
			if err != nil {
				return fmt.Errorf("error refreshing session: %v", err)
			} else if result.StatusCode != 200 {
				return fmt.Errorf("session refresh failed with status code: %d", result.StatusCode)
			} else {
				dbmodels.IIMPSession.AccessToken = result.Response200.Body.SessionToken
				dbmodels.IIMPSession.AccessTokenExpiry = result.Response200.Body.SessionTokenExpiry
				dbmodels.IIMPSession.RefreshToken = result.Response200.Body.RefreshToken
				dbmodels.IIMPSession.SessionExpiry = result.Response200.Body.RefreshTokenExpiry
				err := dbmodels.SaveIIMPSession(dbmodels.IIMPSession)
				if err != nil {
					return fmt.Errorf("error saving session: %v", err)
				}
				// Session Refreshed Successfully
			}
		}

		// load the keys
		err = dbmodels.LoadKeys()
		if err != nil {
			return fmt.Errorf("error loading keys: %v", err)
		}

		// Try to sync events with the server
		err = utils.SyncOnce(cmd.Context(), false)
		if err != nil {
			// Log the error but don't block the user from using the client
			fmt.Fprintf(os.Stderr, "Warning: Failed to sync with server: %v\n", err)
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// nothing in the root command for now
}
