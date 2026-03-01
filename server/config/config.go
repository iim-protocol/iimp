package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
)

type Config struct {
	// Server

	// The port on which the server will listen
	Port int `yaml:"port"`

	// The host address for the server (e.g., "localhost")
	Host string `yaml:"host"`

	// The domain name that clients will use to access the server (e.g., "https://yourdomain.com")
	//
	// DO NOT INCLUDE A TRAILING SLASH IN THE DOMAIN
	Domain string `yaml:"domain"`

	// Server timeout in seconds
	//
	// Default: 15 seconds
	ServerTimeout int `yaml:"serverTimeout"`

	// MongoDB

	// MongoURI is supposed to be read from a file for security reasons
	//
	// Include the dbName in the URI itself, e.g.:
	// mongodb://username:password@localhost:27017/your_database?authSource=authDb
	//
	// Auth source needs to be your database name if you created the user in that database, or "admin" if you created the user in the admin database.
	MongoURIFile string `yaml:"mongoUriFile"`
	mongoURI     string `yaml:"-"` // Unexported field to hold the actual URI after reading from file
	MongoDBName  string `yaml:"mongoDBName"`

	// TLS
	TLS *TLSConfig `yaml:"tls,omitempty"`

	// JWT
	JWTPrivateKeyPath string `yaml:"jwtPrivateKeyPath"`
	JWTPublicKeyPath  string `yaml:"jwtPublicKeyPath"`

	// Expiration time for JWT tokens in seconds (e.g., 3600 for 1 hour)
	//
	// Default: 3600 seconds (1 hour)
	JWTExpirationSeconds int `yaml:"jwtExpirationSeconds"`

	// Clock skew allowance for JWT validation in seconds (e.g., 60 for 1 minute)
	//
	// Default: 30 seconds (30 seconds is a common default, but you can adjust based on your needs)
	JWTClockSkewSeconds int `yaml:"jwtClockSkewSeconds"`

	// Expiration time for server-to-server JWT tokens in seconds (e.g., 60 for 1 minute)
	//
	// Default: 60 seconds (1 minute is a common default for short-lived server tokens, but you can adjust based on your needs)
	JWTServerTokenExpirationSeconds int `yaml:"jwtServerTokenExpirationSeconds"`

	// Session expiration time in seconds (e.g., 2592000 for 30 days)
	//
	// Default: 2592000 seconds (30 days)
	SessionExpiry int `yaml:"sessionExpiry"` // in seconds

	// SignUpDomains is a list of domains that users will be allowed to sign up with.
	//
	// This is not the same as userid, which is iimp specific.
	SignUpDomains []string `yaml:"signUpDomains"`

	// bcrypt cost factor for hashing passwords (e.g., 12)
	//
	// Default: 12
	PasswordBCryptCost int `yaml:"passwordBCryptCost"`
}

type TLSConfig struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

func GetMongoURI() string {
	return C.mongoURI
}

func (c *Config) Validate() error {
	if c.Port == 0 {
		return fmt.Errorf("port is required")
	}
	if c.Host == "" {
		return fmt.Errorf("host is required")
	}
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}

	if c.ServerTimeout == 0 {
		c.ServerTimeout = 15 // Default to 15 seconds
	}

	if c.MongoURIFile == "" {
		return fmt.Errorf("mongoUriFile is required")
	}

	if c.MongoDBName == "" {
		return fmt.Errorf("mongoDBName is required")
	}

	if _, err := os.Stat(c.MongoURIFile); os.IsNotExist(err) {
		return fmt.Errorf("mongoUriFile does not exist: %s", c.MongoURIFile)
	}

	data, err := os.ReadFile(c.MongoURIFile)
	if err != nil {
		return fmt.Errorf("failed to read mongoUriFile: %s", err)
	}
	c.mongoURI = string(data)

	if c.TLS != nil {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("tls.certFile is required")
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.keyFile is required")
		}
	}

	if c.JWTPrivateKeyPath == "" {
		return fmt.Errorf("jwtPrivateKeyPath is required")
	}
	if c.JWTPublicKeyPath == "" {
		return fmt.Errorf("jwtPublicKeyPath is required")
	}
	if c.JWTExpirationSeconds == 0 {
		c.JWTExpirationSeconds = 3600 // Default to 1 hour
	}
	if c.JWTClockSkewSeconds == 0 {
		c.JWTClockSkewSeconds = 30 // Default to 30 seconds
	}
	if c.JWTServerTokenExpirationSeconds == 0 {
		c.JWTServerTokenExpirationSeconds = 60 // Default to 1 minute
	}
	if c.SessionExpiry == 0 {
		c.SessionExpiry = 2592000 // Default to 30 days
	}

	if len(c.SignUpDomains) > 0 {
		// Basic validation to check if each SignUpDomain looks like a valid domain (this is a very basic check and can be improved with regex if needed)
		for _, domain := range c.SignUpDomains {
			if len(domain) < 3 || !strings.Contains(domain, ".") {
				return fmt.Errorf("signUpDomain must be a valid domain")
			}
		}
	} else {
		return fmt.Errorf("signUpDomains are required")
	}

	if c.PasswordBCryptCost == 0 {
		c.PasswordBCryptCost = 12 // Default to 12
	}

	return nil
}

var C *Config

func Load(path string) error {
	C = new(Config)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, C)
	if err != nil {
		return err
	}

	return C.Validate()
}
