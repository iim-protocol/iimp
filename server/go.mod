module github.com/iim-protocol/iimp/server

go 1.25.0

require (
	github.com/MicahParks/jwkset v0.11.0
	github.com/MicahParks/keyfunc/v3 v3.8.0
	github.com/go-chi/chi/v5 v5.2.5
	github.com/goccy/go-yaml v1.19.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/iim-protocol/iimp/sdk/db-models v0.0.0-00010101000000-000000000000
	github.com/iim-protocol/iimp/sdk/iimp_go_client v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.10.2
	go.mongodb.org/mongo-driver/v2 v2.5.0
	golang.org/x/crypto v0.48.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.17.6 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.2.0 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/time v0.9.0 // indirect
)

replace github.com/iim-protocol/iimp/sdk/iimp_go_client => ../sdk/iimp_go_client

replace github.com/iim-protocol/iimp/sdk/db-models => ../sdk/db-models
