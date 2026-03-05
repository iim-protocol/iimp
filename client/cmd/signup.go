/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/iim-protocol/iimp/sdk/iimp_go_client"
	"github.com/spf13/cobra"
)

// signupCmd represents the signup command
var signupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Sign up on an IIMP server.",
	Run: func(cmd *cobra.Command, args []string) {
		var userId, password, displayName, email, serverUrl string

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title("Server URL").Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("server URL cannot be empty")
					}
					return nil
				}).Value(&serverUrl),
			),
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
			huh.NewGroup(
				huh.NewInput().Title("Display Name").Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("display name cannot be empty")
					}
					return nil
				}).Value(&displayName),
				huh.NewInput().Title("Email").Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("email cannot be empty")
					}
					if !strings.Contains(s, "@") || len(strings.Split(s, "@")) != 2 {
						return fmt.Errorf("email must be in the format localpart@domain")
					}
					return nil
				}).Value(&email),
			),
		)

		if err := form.Run(); err != nil {
			fmt.Println("Error:", err)
			return
		}

		iimpClient := iimp_go_client.NewIIMP(serverUrl)
		result, err := iimpClient.SignUp(cmd.Context(), iimp_go_client.SignUpRequest{
			Body: iimp_go_client.SignUpRequestBody{
				DisplayName: displayName,
				Email:       email,
				Password:    password,
				UserId:      userId,
			},
		})
		if err != nil {
			fmt.Println("Error signing up:", err)
		} else if result.StatusCode != 201 {
			fmt.Println("An error occurred while signing up")
		} else {
			fmt.Println("Signed up successfully!")
		}
	},
}

func init() {
	rootCmd.AddCommand(signupCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// signupCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// signupCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
