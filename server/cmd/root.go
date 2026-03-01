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
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "iimp-server",
	Short: "IIMP Server is a reference implementation of the IIMP protocol, designed to facilitate real-time communication over the internet.",
	Long:  `IIMP Server is a reference implementation of the IIMP protocol, designed to facilitate real-time communication over the internet. It provides a robust and scalable server-side solution for handling client connections, managing conversations, and processing messages in accordance with the IIMP specifications.`,
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
	// nothing in the root command for now, but we can add global flags here in the future if needed
}
