package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"jwt-tool/internal/formatter"
	"jwt-tool/internal/keycloak"
	"jwt-tool/internal/keygen"
	"jwt-tool/internal/remote"
	"jwt-tool/internal/resolver"
	"jwt-tool/internal/verifier"
	"jwt-tool/pkg/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var (
	outputFormat string
	secret       string
	pemPath      string
	jwksPath     string
	leeway       string

	keycloakURL   string
	keycloakRealm string
	// Keygen flags
	kgAlg   string
	kgBits  int
	kgCurve string
	kgFile  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "jwt-tool [token|-|@file]",
		Short: "A security-first JWT inspection and verification CLI",
		Long: `A security-first JWT inspection and verification CLI.
By default, it inspects the provided token (or reads from stdin if no argument is given).
If a verification key is provided (--secret, --pem, or --jwks), it also validates the signature and claims.`,
		Args: cobra.MaximumNArgs(1),
		Run:  runInspect,
	}

	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "Output format: json, table, or openid (for keycloak info)")

	inspectCmd := &cobra.Command{
		Use:     "inspect [token|-|@file]",
		Aliases: []string{"decode", "verify"},
		Short:   "Decode and inspect JWT header and claims with optional verification",
		Long: `Decode and inspect JWT header and claims. 
If a verification key is provided (--secret, --pem, or --jwks), it also validates the signature and claims.`,
		Args: cobra.MaximumNArgs(1),
		Run:  runInspect,
	}

	// Add verification flags to both rootCmd and inspectCmd
	for _, cmd := range []*cobra.Command{rootCmd, inspectCmd} {
		cmd.Flags().StringVar(&secret, "secret", "", "Symmetric secret for HMAC verification")
		cmd.Flags().StringVar(&pemPath, "pem", "", "Path to RSA/ECDSA public key PEM file (@path)")
		cmd.Flags().StringVar(&jwksPath, "jwks", "", "Path or URL to JWKS")
		cmd.Flags().StringVar(&leeway, "leeway", "0s", "Clock skew tolerance (e.g. 60s)")
	}

	keycloakCmd := &cobra.Command{
		Use:     "keycloak",
		Aliases: []string{"kc"},
		Short:   "Keycloak integration features",
	}

	keycloakInfoCmd := &cobra.Command{
		Use:   "info",
		Short: "Fetch and display Keycloak OIDC discovery information",
		Run: func(cmd *cobra.Command, args []string) {
			if keycloakURL == "" || keycloakRealm == "" {
				exitWithError("missing required flags", fmt.Errorf("--url and --realm must be specified"))
			}

			if outputFormat == "openid" {
				data, err := keycloak.FetchDiscoveryRaw(keycloakURL, keycloakRealm)
				if err != nil {
					exitWithError("could not fetch discovery document", err)
				}
				fmt.Println(string(data))
				return
			}

			discovery, err := keycloak.FetchDiscovery(keycloakURL, keycloakRealm)
			if err != nil {
				exitWithError("could not fetch discovery document", err)
			}

			render(discovery, nil)
		},
	}

	keycloakInfoCmd.Flags().StringVar(&keycloakURL, "url", "", "Keycloak base URL")
	keycloakInfoCmd.Flags().StringVar(&keycloakRealm, "realm", "", "Keycloak realm name")

	var clientID, clientSecret string
	keycloakIntrospectCmd := &cobra.Command{
		Use:   "introspect [token|-|@file]",
		Short: "Perform server-side token introspection",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if keycloakURL == "" || keycloakRealm == "" || clientID == "" || clientSecret == "" {
				exitWithError("missing required flags", fmt.Errorf("--url, --realm, --client-id, and --client-secret must be specified"))
			}

			input := "-"
			if len(args) > 0 {
				input = args[0]
			}

			tokenData, err := resolver.Resolve(input)
			if err != nil {
				exitWithError("could not resolve token input", err)
			}

			if outputFormat == "json" {
				// We must output the EXACT JSON from Keycloak
				raw, err := keycloak.IntrospectRaw(keycloakURL, keycloakRealm, clientID, clientSecret, string(tokenData))
				if err != nil {
					exitWithError("could not perform introspection", err)
				}
				// Pretty print it as per general tool behavior for -o json
				var pretty json.RawMessage = raw
				out, err := json.MarshalIndent(pretty, "", "  ")
				if err != nil {
					fmt.Println(string(raw)) // Fallback to raw if pretty print fails
				} else {
					fmt.Println(string(out))
				}
				return
			}

			response, err := keycloak.Introspect(keycloakURL, keycloakRealm, clientID, clientSecret, string(tokenData))
			if err != nil {
				exitWithError("could not perform introspection", err)
			}

			render(response, nil)
		},
	}

	keycloakIntrospectCmd.Flags().StringVar(&keycloakURL, "url", "", "Keycloak base URL")
	keycloakIntrospectCmd.Flags().StringVar(&keycloakRealm, "realm", "", "Keycloak realm name")
	keycloakIntrospectCmd.Flags().StringVar(&clientID, "client-id", "", "Keycloak Client ID")
	keycloakIntrospectCmd.Flags().StringVar(&clientSecret, "client-secret", "", "Keycloak Client Secret")

	var username, password, scope string
	keycloakLoginCmd := &cobra.Command{
		Use:   "login",
		Short: "Fetch an access token from Keycloak",
		Run: func(cmd *cobra.Command, args []string) {
			if keycloakURL == "" || keycloakRealm == "" || clientID == "" || clientSecret == "" {
				exitWithError("missing required flags", fmt.Errorf("--url, --realm, --client-id, and --client-secret must be specified"))
			}

			opts := keycloak.LoginOptions{
				BaseURL:      keycloakURL,
				Realm:        keycloakRealm,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Username:     username,
				Password:     password,
				Scope:        scope,
			}

			resp, err := keycloak.Login(opts)
			if err != nil {
				exitWithError("could not perform login", err)
			}

			// Special behavior: if output is not set (default json) but we are in a terminal,
			// we might want just the token. But let's follow the plan:
			// Default: print only access token string if not -o json or -o table
			if cmd.Flag("output").Changed {
				render(resp, nil)
			} else {
				fmt.Println(resp.AccessToken)
			}
		},
	}

	keycloakLoginCmd.Flags().StringVar(&keycloakURL, "url", "", "Keycloak base URL")
	keycloakLoginCmd.Flags().StringVar(&keycloakRealm, "realm", "", "Keycloak realm name")
	keycloakLoginCmd.Flags().StringVar(&clientID, "client-id", "", "Keycloak Client ID")
	keycloakLoginCmd.Flags().StringVar(&clientSecret, "client-secret", "", "Keycloak Client Secret")
	keycloakLoginCmd.Flags().StringVar(&username, "username", "", "Username (for password grant)")
	keycloakLoginCmd.Flags().StringVar(&password, "password", "", "Password (for password grant)")
	keycloakLoginCmd.Flags().StringVar(&scope, "scope", "openid", "Token scope")

	keycloakCmd.AddCommand(keycloakInfoCmd, keycloakIntrospectCmd, keycloakLoginCmd)
	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new asymmetric key pair (RSA or ECDSA) in PEM format",
		Run:   runKeygen,
	}

	keygenCmd.Flags().StringVarP(&kgAlg, "alg", "a", "rsa", "Algorithm: rsa or ecdsa")
	keygenCmd.Flags().IntVarP(&kgBits, "bits", "b", 2048, "RSA bit size: 2048, 3072, 4096")
	keygenCmd.Flags().StringVarP(&kgCurve, "curve", "c", "P256", "ECDSA curve: P256, P384, P521")
	keygenCmd.Flags().StringVarP(&kgFile, "file", "f", "", "Save to file (e.g. 'id_rsa' creates 'id_rsa' and 'id_rsa.pub')")

	rootCmd.AddCommand(inspectCmd, keycloakCmd, keygenCmd)
	if err := rootCmd.Execute(); err != nil {
		exitWithError("execution failed", err)
	}
}

func runInspect(cmd *cobra.Command, args []string) {
	input := "-"
	if len(args) > 0 {
		input = args[0]
	}

	data, err := resolver.Resolve(input)
	if err != nil {
		exitWithError("could not resolve input", err)
	}

	// Step 1: Always Decode
	info, err := verifier.Decode(string(data))
	if err != nil {
		exitWithError("could not decode token", err)
	}

	validationFailed := false

	// Step 2: Attempt verification if keys are provided
	if secret != "" || pemPath != "" || jwksPath != "" {
		opts := verifier.VerifyOptions{
			Algorithms: []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"},
		}

		if secret != "" {
			s, err := resolver.Resolve(secret)
			if err != nil {
				exitWithError("could not resolve secret", err)
			}
			opts.Secret = s
		}

		if pemPath != "" {
			p, err := resolver.Resolve(pemPath)
			if err != nil {
				exitWithError("could not resolve PEM path", err)
			}
			pub, err := jwt.ParseRSAPublicKeyFromPEM(p)
			if err != nil {
				// Try ECDSA if RSA fails
				pubEC, errEC := jwt.ParseECPublicKeyFromPEM(p)
				if errEC != nil {
					exitWithError("could not parse PEM", fmt.Errorf("tried RSA and ECDSA: %v", err))
				}
				opts.PublicKey = pubEC
			} else {
				opts.PublicKey = pub
			}
		}

		if jwksPath != "" {
			jwks, err := remote.LoadJWKS(jwksPath)
			if err != nil {
				exitWithError("could not load JWKS", err)
			}
			opts.JWKS = jwks
		}

		if leeway != "" {
			d, err := time.ParseDuration(leeway)
			if err != nil {
				exitWithError("could not parse leeway duration", err)
			}
			opts.Leeway = d
		}

		alg, _ := info.Header["alg"].(string)

		_, err = verifier.Verify(string(data), opts)
		if err != nil {
			info.Validation = &models.ValidationInfo{
				Valid:     false,
				Status:    "INVALID",
				Error:     err.Error(),
				Algorithm: alg,
			}
			validationFailed = true
		} else {
			info.Validation = &models.ValidationInfo{
				Valid:     true,
				Status:    "VALID",
				Algorithm: alg,
			}
		}
	}

	// Step 3: Unified Render
	render(info, nil)

	// Step 4: Conditional Exit
	if validationFailed {
		os.Exit(2)
	}
}

func runKeygen(cmd *cobra.Command, args []string) {
	var kp *keygen.KeyPair
	var err error

	switch kgAlg {
	case "rsa":
		kp, err = keygen.GenerateRSA(kgBits)
	case "ecdsa":
		kp, err = keygen.GenerateECDSA(kgCurve)
	default:
		exitWithError("unsupported algorithm", fmt.Errorf("%s", kgAlg))
	}

	if err != nil {
		exitWithError("could not generate keys", err)
	}

	if kgFile != "" {
		privFile := kgFile
		pubFile := kgFile + ".pub"

		if err := os.WriteFile(privFile, kp.PrivatePEM, 0600); err != nil {
			exitWithError("could not write private key", err)
		}
		if err := os.WriteFile(pubFile, kp.PublicPEM, 0644); err != nil {
			exitWithError("could not write public key", err)
		}
		fmt.Printf("Keys saved to %s and %s\n", privFile, pubFile)
	} else {
		fmt.Print(string(kp.PrivatePEM))
		fmt.Print(string(kp.PublicPEM))
	}
}

func exitWithError(context string, err error) {
	fmt.Fprintf(os.Stderr, "Error: %s: %v\n", context, err)
	os.Exit(1)
}

func render(info interface{}, message *string) {
	switch outputFormat {
	case "table":
		if tokenInfo, ok := info.(*models.TokenInfo); ok {
			formatter.PrintTokenSummary(tokenInfo)
		} else if discovery, ok := info.(*models.KeycloakDiscovery); ok {
			formatter.PrintKeycloakTable(discovery)
		} else if introspection, ok := info.(models.IntrospectionResponse); ok {
			formatter.PrintIntrospectionTable(introspection)
		} else if tokenResp, ok := info.(*models.TokenResponse); ok {
			formatter.PrintLoginTable(tokenResp)
		} else {
			// Fallback
			out, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				exitWithError("could not format JSON", err)
			}
			fmt.Println(string(out))
		}
		if message != nil {
			fmt.Printf("\n%s\n", *message)
		}
	default:
		out, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			exitWithError("could not format JSON", err)
		}
		fmt.Println(string(out))
	}
}

func ptr(s string) *string {
	return &s
}
