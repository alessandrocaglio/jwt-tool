package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"jwt-tool/internal/formatter"
	"jwt-tool/internal/jwks"
	"jwt-tool/internal/keycloak"
	"jwt-tool/internal/keygen"
	"jwt-tool/internal/oidc"
	"jwt-tool/internal/remote"
	"jwt-tool/internal/resolver"
	"jwt-tool/internal/signer"
	"jwt-tool/internal/verifier"
	"jwt-tool/pkg/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	outputFormat string
	secret       string
	pemPath      string
	jwksPath     string
	leeway       string

	keycloakURL   string
	keycloakRealm string
	oidcIssuer    string
	// Keygen flags
	kgAlg    string
	kgBits   int
	kgCurve  string
	kgFile   string
	jwksKids []string

	// Create flags
	createAlg     string
	createSecret  string
	createPem     string
	createPayload string
	createClaims  []string
	createHeaders []string
	createExp     string
	createNbf     string
	createIat     string
	createIss     string
	createSub     string
	createAud     string
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
		cmd.Flags().StringVar(&pemPath, "pem", "", "Path to RSA/ECDSA/EdDSA public key PEM file (@path)")
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

	oidcCmd := &cobra.Command{
		Use:   "oidc",
		Short: "OIDC integration features",
	}

	oidcInfoCmd := &cobra.Command{
		Use:   "info",
		Short: "Fetch and display OIDC discovery information",
		Run: func(cmd *cobra.Command, args []string) {
			if oidcIssuer == "" {
				exitWithError("missing required flags", fmt.Errorf("--issuer must be specified"))
			}

			if outputFormat == "openid" {
				data, err := oidc.FetchDiscoveryRaw(oidcIssuer)
				if err != nil {
					exitWithError("could not fetch discovery document", err)
				}
				fmt.Println(string(data))
				return
			}

			discovery, err := oidc.FetchDiscovery(oidcIssuer)
			if err != nil {
				exitWithError("could not fetch discovery document", err)
			}

			render(discovery, nil)
		},
	}
	oidcInfoCmd.Flags().StringVar(&oidcIssuer, "issuer", "", "OIDC issuer URL")

	oidcIntrospectCmd := &cobra.Command{
		Use:   "introspect [token|-|@file]",
		Short: "Perform server-side token introspection",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if oidcIssuer == "" || clientID == "" || clientSecret == "" {
				exitWithError("missing required flags", fmt.Errorf("--issuer, --client-id, and --client-secret must be specified"))
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
				raw, err := oidc.IntrospectRaw(oidcIssuer, clientID, clientSecret, string(tokenData))
				if err != nil {
					exitWithError("could not perform introspection", err)
				}
				var pretty json.RawMessage = raw
				out, err := json.MarshalIndent(pretty, "", "  ")
				if err != nil {
					fmt.Println(string(raw))
				} else {
					fmt.Println(string(out))
				}
				return
			}

			response, err := oidc.Introspect(oidcIssuer, clientID, clientSecret, string(tokenData))
			if err != nil {
				exitWithError("could not perform introspection", err)
			}

			render(response, nil)
		},
	}
	oidcIntrospectCmd.Flags().StringVar(&oidcIssuer, "issuer", "", "OIDC issuer URL")
	oidcIntrospectCmd.Flags().StringVar(&clientID, "client-id", "", "OIDC Client ID")
	oidcIntrospectCmd.Flags().StringVar(&clientSecret, "client-secret", "", "OIDC Client Secret")

	oidcLoginCmd := &cobra.Command{
		Use:   "login",
		Short: "Fetch an access token from an OIDC provider",
		Run: func(cmd *cobra.Command, args []string) {
			if oidcIssuer == "" || clientID == "" || clientSecret == "" {
				exitWithError("missing required flags", fmt.Errorf("--issuer, --client-id, and --client-secret must be specified"))
			}

			opts := oidc.LoginOptions{
				Issuer:       oidcIssuer,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Username:     username,
				Password:     password,
				Scope:        scope,
			}

			resp, err := oidc.Login(opts)
			if err != nil {
				exitWithError("could not perform login", err)
			}

			if cmd.Flag("output").Changed {
				render(resp, nil)
			} else {
				fmt.Println(resp.AccessToken)
			}
		},
	}
	oidcLoginCmd.Flags().StringVar(&oidcIssuer, "issuer", "", "OIDC issuer URL")
	oidcLoginCmd.Flags().StringVar(&clientID, "client-id", "", "OIDC Client ID")
	oidcLoginCmd.Flags().StringVar(&clientSecret, "client-secret", "", "OIDC Client Secret")
	oidcLoginCmd.Flags().StringVar(&username, "username", "", "Username (for password grant)")
	oidcLoginCmd.Flags().StringVar(&password, "password", "", "Password (for password grant)")
	oidcLoginCmd.Flags().StringVar(&scope, "scope", "openid", "Token scope")

	oidcCmd.AddCommand(oidcInfoCmd, oidcIntrospectCmd, oidcLoginCmd)
	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new asymmetric key pair (RSA, ECDSA, or EdDSA) in PEM format",
		Run:   runKeygen,
	}

	keygenCmd.Flags().StringVarP(&kgAlg, "alg", "a", "rsa", "Algorithm: rsa, ecdsa, or eddsa")
	keygenCmd.Flags().IntVarP(&kgBits, "bits", "b", 2048, "RSA bit size: 2048, 3072, 4096")
	keygenCmd.Flags().StringVarP(&kgCurve, "curve", "c", "P256", "ECDSA curve: P256, P384, P521")
	keygenCmd.Flags().StringVarP(&kgFile, "file", "f", "", "Save to file (e.g. 'id_rsa' creates 'id_rsa' and 'id_rsa.pub')")

	jwksCmd := &cobra.Command{
		Use:   "jwks [key-input]...",
		Short: "Convert public keys to JSON Web Key Set (JWKS)",
		Run:   runJwks,
	}

	jwksCmd.Flags().StringSliceVar(&jwksKids, "kid", []string{}, "Key ID for each key (repeatable)")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("jwt-tool version: %s\n", version)
			fmt.Printf("commit: %s\n", commit)
			fmt.Printf("build date: %s\n", date)
		},
	}

	rootCmd.AddCommand(inspectCmd, keycloakCmd, oidcCmd, keygenCmd, createCmd, versionCmd, jwksCmd)
	if err := rootCmd.Execute(); err != nil {
		exitWithError("execution failed", err)
	}
}

var createCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"sign"},
	Short:   "Create and sign a new JWT",
	Long: `Create and sign a new JWT from scratch.
	Example:
	jwt-tool create --alg HS256 --secret "my-secret" --sub "user123" --exp 1h`,
	Run: runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createAlg, "alg", "HS256", "Algorithm: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, EdDSA")
	createCmd.Flags().StringVar(&createSecret, "secret", "", "Symmetric secret for HMAC")
	createCmd.Flags().StringVar(&createPem, "pem", "", "Path to private key PEM file (@path)")
	createCmd.Flags().StringVar(&createPayload, "payload", "", "Path to JSON file for bulk payload (@path)")
	createCmd.Flags().StringSliceVar(&createClaims, "claim", []string{}, "Custom claims in key=value format (repeatable)")
	createCmd.Flags().StringSliceVar(&createHeaders, "header", []string{}, "Custom header fields in key=value format (repeatable)")
	createCmd.Flags().StringVar(&createExp, "exp", "", "Expiration time (shorthand duration, e.g. 1h, 1d)")
	createCmd.Flags().StringVar(&createNbf, "nbf", "", "Not before time (shorthand duration, e.g. 1m)")
	createCmd.Flags().StringVar(&createIat, "iat", "0s", "Issued at time (offset duration, default 0s means now)")
	createCmd.Flags().StringVar(&createIss, "iss", "", "Issuer claim")
	createCmd.Flags().StringVar(&createSub, "sub", "", "Subject claim")
	createCmd.Flags().StringVar(&createAud, "aud", "", "Audience claim")
}

func runCreate(cmd *cobra.Command, args []string) {
	opts := signer.SignOptions{
		Algorithm: createAlg,
		Claims:    jwt.MapClaims{},
		Header:    make(map[string]interface{}),
	}

	// 1. Resolve Keys
	if createSecret != "" {
		s, err := resolver.Resolve(createSecret)
		if err != nil {
			exitWithError("could not resolve secret", err)
		}
		opts.Secret = s
	}

	if createPem != "" {
		p, err := resolver.Resolve(createPem)
		if err != nil {
			exitWithError("could not resolve PEM path", err)
		}

		// Try to parse as private keys
		if priv, err := jwt.ParseRSAPrivateKeyFromPEM(p); err == nil {
			opts.PrivateKey = priv
		} else if priv, err := jwt.ParseECPrivateKeyFromPEM(p); err == nil {
			opts.PrivateKey = priv
		} else if priv, err := jwt.ParseEdPrivateKeyFromPEM(p); err == nil {
			opts.PrivateKey = priv
		} else {
			exitWithError("could not parse private key PEM", fmt.Errorf("tried RSA, ECDSA, and EdDSA"))
		}
	}

	// 2. Load Payload File
	if createPayload != "" {
		data, err := resolver.Resolve(createPayload)
		if err != nil {
			exitWithError("could not resolve payload file", err)
		}
		if err := json.Unmarshal(data, &opts.Claims); err != nil {
			exitWithError("could not parse payload JSON", err)
		}
	}

	// 3. Apply Shorthand Claims
	now := time.Now()
	if createExp != "" {
		d, err := time.ParseDuration(createExp)
		if err != nil {
			exitWithError("invalid exp duration", err)
		}
		opts.Claims["exp"] = jwt.NewNumericDate(now.Add(d))
	}
	if createNbf != "" {
		d, err := time.ParseDuration(createNbf)
		if err != nil {
			exitWithError("invalid nbf duration", err)
		}
		opts.Claims["nbf"] = jwt.NewNumericDate(now.Add(d))
	}
	if createIat != "" {
		d, err := time.ParseDuration(createIat)
		if err != nil {
			exitWithError("invalid iat duration", err)
		}
		opts.Claims["iat"] = jwt.NewNumericDate(now.Add(d))
	}
	if createIss != "" {
		opts.Claims["iss"] = createIss
	}
	if createSub != "" {
		opts.Claims["sub"] = createSub
	}
	if createAud != "" {
		opts.Claims["aud"] = createAud
	}

	// 4. Parse Individual Claims
	for _, c := range createClaims {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			exitWithError("invalid claim format", fmt.Errorf("expected key=value, got %s", c))
		}
		// Try to parse as JSON if it looks like one, otherwise treat as string
		var val interface{}
		if err := json.Unmarshal([]byte(parts[1]), &val); err != nil {
			val = parts[1]
		}
		opts.Claims[parts[0]] = val
	}

	// 5. Parse Individual Headers
	for _, h := range createHeaders {
		parts := strings.SplitN(h, "=", 2)
		if len(parts) != 2 {
			exitWithError("invalid header format", fmt.Errorf("expected key=value, got %s", h))
		}
		var val interface{}
		if err := json.Unmarshal([]byte(parts[1]), &val); err != nil {
			val = parts[1]
		}
		opts.Header[parts[0]] = val
	}

	// 6. Security Warnings
	if _, ok := opts.Claims["exp"]; !ok {
		fmt.Fprintf(os.Stderr, "warning: no expiration ('exp') claim provided. The token will never expire.\n")
	} else if exp, ok := opts.Claims["exp"].(*jwt.NumericDate); ok {
		if exp.Time.Sub(now) > 24*time.Hour {
			fmt.Fprintf(os.Stderr, "warning: expiration is more than 24 hours in the future.\n")
		}
	}

	// 7. Sign
	token, err := signer.Sign(opts)
	if err != nil {
		exitWithError("could not sign token", err)
	}

	// 8. Output
	if cmd.Flag("output").Changed {
		if outputFormat == "json" || outputFormat == "table" {
			info, err := verifier.Decode(token)
			if err != nil {
				exitWithError("could not decode signed token for output", err)
			}
			render(info, nil)
		} else {
			fmt.Println(token)
		}
	} else {
		fmt.Println(token)
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
	leewayDisplay := "0s"

	// Step 2: Attempt verification if keys are provided
	if secret != "" || pemPath != "" || jwksPath != "" {
		opts := verifier.VerifyOptions{
			Algorithms: []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"},
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

			// Try to parse as RSA, then ECDSA, then EdDSA
			if pub, err := jwt.ParseRSAPublicKeyFromPEM(p); err == nil {
				opts.PublicKey = pub
			} else if pub, err := jwt.ParseECPublicKeyFromPEM(p); err == nil {
				opts.PublicKey = pub
			} else if pub, err := jwt.ParseEdPublicKeyFromPEM(p); err == nil {
				opts.PublicKey = pub
			} else {
				exitWithError("could not parse PEM", fmt.Errorf("tried RSA, ECDSA, and EdDSA public keys"))
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

			if d > 5*time.Minute {
				fmt.Fprintf(os.Stderr, "warning: leeway of %s is unusually large and may accept significantly expired tokens\n", d)
			}

			opts.Leeway = d
			leewayDisplay = d.String()
		}

		alg, _ := info.Header["alg"].(string)

		_, err = verifier.Verify(string(data), opts)
		if err != nil {
			info.Validation = &models.ValidationInfo{
				Valid:     false,
				Status:    "INVALID",
				Error:     err.Error(),
				Algorithm: alg,
				Leeway:    leewayDisplay,
			}
			validationFailed = true
		} else {
			info.Validation = &models.ValidationInfo{
				Valid:     true,
				Status:    "VALID",
				Algorithm: alg,
				Leeway:    leewayDisplay,
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
	case "eddsa":
		kp, err = keygen.GenerateEdDSA()
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
		} else if discovery, ok := info.(*models.OIDCDiscovery); ok {
			formatter.PrintOIDCTable(discovery)
		} else if introspection, ok := info.(models.IntrospectionResponse); ok {
			formatter.PrintIntrospectionTable(introspection)
		} else if tokenResp, ok := info.(*models.OIDCTokenResponse); ok {
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

func runJwks(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		args = []string{"-"}
	}

	var pubKeys []interface{}
	for _, arg := range args {
		data, err := resolver.Resolve(arg)
		if err != nil {
			exitWithError(fmt.Sprintf("could not resolve input %s", arg), err)
		}

		if pub, err := jwt.ParseRSAPublicKeyFromPEM(data); err == nil {
			pubKeys = append(pubKeys, pub)
		} else if pub, err := jwt.ParseECPublicKeyFromPEM(data); err == nil {
			pubKeys = append(pubKeys, pub)
		} else if pub, err := jwt.ParseEdPublicKeyFromPEM(data); err == nil {
			pubKeys = append(pubKeys, pub)
		} else {
			exitWithError("could not parse public key", fmt.Errorf("tried RSA, ECDSA, and EdDSA for %s", arg))
		}
	}

	jwkSet, err := jwks.GenerateJWKS(pubKeys, jwksKids)
	if err != nil {
		exitWithError("could not generate JWKS", err)
	}

	render(jwkSet, nil)
}
