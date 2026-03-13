/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/iim-protocol/iimp/client/utils"
	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to an IIMP server.",
	Run: func(cmd *cobra.Command, args []string) {
		if sessionExists, _ := dbmodels.LoadIIMPSession(); sessionExists {
			fmt.Println("Existing session found. Please logout first if you want to login again.")
			return
		}
		var userId, password, serverUrl string

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title("User ID").Description("(localpart@domain)").Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("user ID cannot be empty")
					}
					if !strings.Contains(s, "@") || len(strings.Split(s, "@")) != 2 {
						return fmt.Errorf("user ID must be in the format localpart@domain")
					}
					return nil
				}).Value(&userId),
				huh.NewInput().Title("Password").EchoMode(huh.EchoModePassword).Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("password cannot be empty")
					}
					return nil
				}).Value(&password),
			),
		)

		if err := form.Run(); err != nil {
			cmd.Printf("Error running form: %v\n", err)
			return
		}

		domain, err := utils.ExtractDomainFromUserId(userId)
		if err != nil {
			fmt.Println("Error extracting domain from user ID:", err)
			return
		}
		serverUrl = "https://" + domain

		client := iimp_go_client.NewIIMP(serverUrl)
		result, err := client.Login(cmd.Context(), iimp_go_client.LoginRequest{
			Body: iimp_go_client.LoginRequestBody{
				UserId:   userId,
				Password: password,
			},
		})
		if err != nil {
			fmt.Printf("Error logging in: %v\n", err)
			return
		} else if result.StatusCode != 200 {
			fmt.Printf("Login failed with status code: %d\n", result.StatusCode)
			return
		} else {
			sessionFile := &dbmodels.IIMPSessionFile{
				ServerUrl:         serverUrl,
				UserId:            userId,
				AccessToken:       result.Response200.Body.SessionToken,
				AccessTokenExpiry: result.Response200.Body.SessionTokenExpiry,
				RefreshToken:      result.Response200.Body.RefreshToken,
				SessionExpiry:     result.Response200.Body.RefreshTokenExpiry,
			}
			err = dbmodels.SaveIIMPSession(sessionFile)
			if err != nil {
				fmt.Printf("Error saving session: %v\n", err)
				return
			}
			fmt.Println("Login successful!")
			keypairExists, err := dbmodels.KeypairExistsForServerAndUser(userId, serverUrl)
			if err != nil {
				fmt.Printf("Error checking for existing keypair: %v\n", err)
				return
			}
			if keypairExists {
				fmt.Println("Existing keypair found for this server and user. Skipping key generation.")
				return
			}
			fmt.Println("Generating X25519 keypair for this server...")
			localKeyPair, err := dbmodels.GenerateAndSaveKeys(userId, serverUrl)
			if err != nil {
				fmt.Println("Error generating keypair:", err)
				return
			}

			authorization := "Bearer " + result.Response200.Body.SessionToken
			resultPubKey, err := client.AddPublicKey(cmd.Context(), iimp_go_client.AddPublicKeyRequest{
				Auth: iimp_go_client.AddPublicKeyRequestAuthParams{
					Authorization: &authorization,
				},
				Body: iimp_go_client.AddPublicKeyRequestBody{
					KeyId:     localKeyPair.KeyID,
					PublicKey: localKeyPair.PublicKeyEncoded,
					Timestamp: time.Now().Format(time.RFC3339),
				},
			})
			if err != nil {
				fmt.Println("Error adding public key:", err)
				return
			}
			if resultPubKey.StatusCode != 201 {
				fmt.Printf("Failed to add public key with status code: %d\n", resultPubKey.StatusCode)
				return
			}
			fmt.Printf("Generated keypair with KeyID (%s) successfully!\n", localKeyPair.KeyID)
		}
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
