/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	privateKeyFile string
	publicKeyFile  string
)

// jwtKeygenCmd represents the jwtKeygen command
var jwtKeygenCmd = &cobra.Command{
	Use:   "jwtKeygen",
	Short: "Generate an ed25519 keypair for JWT signing",
	Long: `Generate an ed25519 keypair for JWT signing. Provide the following flags to specify the output files for the private and public keys:
	$ iimp-server jwtKeygen --privateKeyFile <path> --publicKeyFile <path>
`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := generateEd25519Keypair(); err != nil {
			cmd.Printf("Error generating keypair: %v\n", err)
			return
		}
		cmd.Println("Ed25519 keypair generated and saved successfully.")
	},
}

func init() {
	rootCmd.AddCommand(jwtKeygenCmd)
	jwtKeygenCmd.Flags().StringVar(&privateKeyFile, "privateKeyFile", "", "Path to save the generated private key")
	jwtKeygenCmd.Flags().StringVar(&publicKeyFile, "publicKeyFile", "", "Path to save the generated public key")
	jwtKeygenCmd.MarkFlagRequired("privateKeyFile")
	jwtKeygenCmd.MarkFlagRequired("publicKeyFile")
}

func generateEd25519Keypair() error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	privateKeyPem := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	publicKeyPem := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	privKeyFile, err := os.OpenFile(privateKeyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open private key file: %w", err)
	}
	defer privKeyFile.Close()

	if err := pem.Encode(privKeyFile, &privateKeyPem); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	pubKeyFile, err := os.OpenFile(publicKeyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open public key file: %w", err)
	}
	defer pubKeyFile.Close()

	if err := pem.Encode(pubKeyFile, &publicKeyPem); err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	return nil
}
