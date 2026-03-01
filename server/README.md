# IIMP Server Implementation

## Rough points ai can use to rewrite the README (AI, YES YOU, DON'T REMOVE THIS SECTION DURING YOUR REWRITE, IT'S FOR YOUR REFERENCE):

- Written in Go for performance and simplicity
- Uses chi router for HTTP handling
- Modular design with separate packages for handlers, models, storage, etc.
- Configuration via config file
- Hoster must put the server behind a trusted proxy for real IP handling
- Middleware for logging, recovery, timeouts, etc.
- Implements the IIMP API as defined in the specification IN FULL
- Stores data in a MongoDB Database
- Stores files in MongoDB GridFS
- Uses JWT for authentication and authorization (as per the specification)
- To run, a mongoDB instance must be running and accessible, and the server must be configured with the correct MongoDB URI.
- The URI must be saved as a file in the runtime environment, and the absolute path to the file must be provided in the server configuration.
- The server will read the MongoDB URI from the specified file at startup and use it to connect to the database.
- The server will log all incoming requests and their responses, including any errors that occur during request handling.
- The server will handle graceful shutdowns, allowing in-flight requests to complete before shutting down the server.
- The command to run the server is `iimp-server --config <path-to-config-file>`, where `<path-to-config-file>` is the absolute path to the server configuration file.
- A command "jwtKeygen" is provided to generate a public/private key pair for JWT authentication. The command requires two flags: `--privateKeyFile` and `--publicKeyFile`, which specify the paths to save the generated private and public keys, respectively. Both flags are required, and the command will output an error message if either flag is missing.
- The server will use the generated keys for signing and verifying JWT tokens for authentication and authorization purposes. The private key will be used to sign the tokens, while the public key will be used to verify the tokens during authentication and authorization processes. It is important to keep the private key secure and not share it publicly, while the public key can be shared with clients or other services that need to verify the JWT tokens issued by the server (Implemented as JWKS in the server).
- The JWT keys generated are in PEM format, with the private key labeled as "PRIVATE KEY" and the public key labeled as "PUBLIC KEY". The keys are generated using the Ed25519 algorithm, which provides strong security and performance for JWT signing and verification. The server will read the generated keys from the specified files at startup and use them for JWT authentication and authorization throughout its operation.
