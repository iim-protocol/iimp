/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/config"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/handlers"
	"github.com/spf13/cobra"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the server to listen for incoming requests and handle them according to the IIMP protocol.",
	Run: func(cmd *cobra.Command, args []string) {
		startServer(cmd)
	},
}

var configPath string

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to IIMP Server Configuration file")
}

func startServer(cmd *cobra.Command) {
	// Load configuration
	if configPath == "" {
		cmd.Println("Error: --config (-c) flag is required")
		return
	}
	err := config.Load(configPath)
	if err != nil {
		cmd.Println("Error loading config:", err)
		return
	}

	ctxBootstrap, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load JWT signing keys
	if err := auth.Init(ctxBootstrap, config.C.JWTPrivateKeyPath, config.C.JWTPublicKeyPath); err != nil {
		cmd.Println("Error initializing JWT signing keys:", err)
		return
	}

	// init mongodb connection
	if err := db.Connect(ctxBootstrap, config.GetMongoURI()); err != nil {
		cmd.Println("Error connecting to MongoDB:", err)
		return
	}

	// Create router
	r := chi.NewRouter()

	// Add middlewares
	r.Use(middleware.SupressNotFound(r))
	r.Use(middleware.RealIP) // Get the real IP from the request headers (HOSTER MUST PUT THE SERVER BEHIND A TRUSTED PROXY)
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(time.Duration(config.C.ServerTimeout) * time.Second))
	r.Use(middleware.CleanPath)
	r.Use(middleware.StripSlashes)

	// Register handlers
	handlers.RegisterHandlers(r)

	// Start the server, listen on the configured port
	// If TLS is enabled in the config, use ListenAndServeTLS, otherwise use ListenAndServe
	addr := fmt.Sprintf("%s:%d", config.C.Host, config.C.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	go func() {
		if config.C.TLS != nil {
			cmd.Printf("Starting IIMP Server with TLS on port %d...\n", config.C.Port)
			err := srv.ListenAndServeTLS(config.C.TLS.CertFile, config.C.TLS.KeyFile)
			if err != nil && err != http.ErrServerClosed {
				cmd.Println("Error starting server with TLS:", err)
			}
		} else {
			cmd.Printf("Starting IIMP Server on port %d...\n", config.C.Port)
			err := srv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				cmd.Println("Error starting server:", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	cmd.Println("Shutting down server...")

	// Attempt graceful shutdown with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.C.ServerTimeout)*time.Second)
	defer cancel()
	if err := db.Disconnect(ctx); err != nil {
		cmd.Println("Error disconnecting from MongoDB:", err)
	}
	if err := srv.Shutdown(ctx); err != nil {
		cmd.Println("Server forced to shutdown:", err)
	} else {
		cmd.Println("Server gracefully stopped")
	}
}
