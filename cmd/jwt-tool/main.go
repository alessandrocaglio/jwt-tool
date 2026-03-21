package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"jwt-tool/internal/formatter"
	"jwt-tool/internal/jwks"
	"jwt-tool/internal/keycloak"
	"jwt-tool/internal/keygen"
	"jwt-tool/internal/keys"
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

	// Root flags
	outputFormat string
)

type inspectOptions struct {
	secret string
	pem    string
	jwks   string
	leeway string
}

type keycloakOptions struct {
	url          string
	realm        string
	clientID     string
	clientSecret string
	username     string
	password     string
	scope        string
}

type oidcOptions struct {
	issuer       string
	clientID     string
	clientSecret string
	username     string
	password     string
	scope        string
}

type keygenOptions struct {
	alg   string
	bits  int
	curve string
	file  string
}

type jwksOptions struct {
	kids []string
}

type createOptions struct {
	alg     string
	secret  string
	pem     string
	payload string
	claims  []string
	headers []string
	exp     string
	nbf     string
	iat     string
	iss     string
	sub     string
	aud     string
}

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	opts := &inspectOptions{}

	rootCmd := &cobra.Command{
		Use:   "jwt-tool [token|-|@file]",
		Short: "A security-first JWT inspection and verification CLI",
		Long: `A security-first JWT inspection and verification CLI.
	By default, it inspects the provided token (or reads from stdin if no argument is given).
	If a verification key is provided (--secret, --pem, or --jwks), it also validates the signature and claims.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(cmd, args, opts)
		},
	}

	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "Output format: json, table, or openid (for keycloak info)")

	rootCmd.Flags().StringVar(&opts.secret, "secret", "", "Symmetric secret for HMAC verification")
	rootCmd.Flags().StringVar(&opts.pem, "pem", "", "Path to RSA/ECDSA/EdDSA public key PEM file (@path)")
	rootCmd.Flags().StringVar(&opts.jwks, "jwks", "", "Path or URL to JWKS")
	rootCmd.Flags().StringVar(&opts.leeway, "leeway", "0s", "Clock skew tolerance (e.g. 60s)")

	rootCmd.AddCommand(
		newInspectCmd(),
		newKeycloakCmd(),
		newOIDCCmd(),
		newKeygenCmd(),
		newCreateCmd(),
		newVersionCmd(),
		newJwksCmd(),
	)

	return rootCmd
}

func newInspectCmd() *cobra.Command {
	opts := &inspectOptions{}
	cmd := &cobra.Command{
		Use:     "inspect [token|-|@file]",
		Aliases: []string{"decode", "verify"},
		Short:   "Decode and inspect JWT header and claims with optional verification",
		Long: `Decode and inspect JWT header and claims. 
	If a verification key is provided (--secret, --pem, or --jwks), it also validates the signature and claims.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(cmd, args, opts)
		},
	}

	cmd.Flags().StringVar(&opts.secret, "secret", "", "Symmetric secret for HMAC verification")
	cmd.Flags().StringVar(&opts.pem, "pem", "", "Path to RSA/ECDSA/EdDSA public key PEM file (@path)")
	cmd.Flags().StringVar(&opts.jwks, "jwks", "", "Path or URL to JWKS")
	cmd.Flags().StringVar(&opts.leeway, "leeway", "0s", "Clock skew tolerance (e.g. 60s)")

	return cmd
}

func newKeycloakCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "keycloak",
		Aliases: []string{"kc"},
		Short:   "Keycloak integration features",
	}

	opts := &keycloakOptions{}

	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Fetch and display Keycloak OIDC discovery information",
		RunE: func(cmd *cobra.Command, args []string) error {
			discovery, err := keycloak.FetchDiscovery(opts.url, opts.realm)
			if err != nil {
				return fmt.Errorf("could not fetch discovery document: %w", err)
			}

			return render(discovery, nil)
		},
	}
	infoCmd.Flags().StringVar(&opts.url, "url", "", "Keycloak base URL")
	infoCmd.Flags().StringVar(&opts.realm, "realm", "", "Keycloak realm name")

	introspectCmd := &cobra.Command{
		Use:   "introspect [token|-|@file]",
		Short: "Perform server-side token introspection",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.url == "" || opts.realm == "" || opts.clientID == "" || opts.clientSecret == "" {
				return fmt.Errorf("--url, --realm, --client-id, and --client-secret must be specified")
			}

			input := "-"
			if len(args) > 0 {
				input = args[0]
			}

			tokenData, err := resolver.Resolve(input)
			if err != nil {
				return fmt.Errorf("could not resolve token input: %w", err)
			}

			if outputFormat == "json" {
				raw, err := keycloak.IntrospectRaw(opts.url, opts.realm, opts.clientID, opts.clientSecret, string(tokenData))
				if err != nil {
					return fmt.Errorf("could not perform introspection: %w", err)
				}
				var pretty json.RawMessage = raw
				out, err := json.MarshalIndent(pretty, "", "  ")
				if err != nil {
					fmt.Println(string(raw))
				} else {
					fmt.Println(string(out))
				}
				return nil
			}

			response, err := keycloak.Introspect(opts.url, opts.realm, opts.clientID, opts.clientSecret, string(tokenData))
			if err != nil {
				return fmt.Errorf("could not perform introspection: %w", err)
			}

			return render(response, nil)
		},
	}
	introspectCmd.Flags().StringVar(&opts.url, "url", "", "Keycloak base URL")
	introspectCmd.Flags().StringVar(&opts.realm, "realm", "", "Keycloak realm name")
	introspectCmd.Flags().StringVar(&opts.clientID, "client-id", "", "Keycloak Client ID")
	introspectCmd.Flags().StringVar(&opts.clientSecret, "client-secret", "", "Keycloak Client Secret")

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Fetch an access token from Keycloak",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.url == "" || opts.realm == "" || opts.clientID == "" || opts.clientSecret == "" {
				return fmt.Errorf("--url, --realm, --client-id, and --client-secret must be specified")
			}

			loginOpts := keycloak.LoginOptions{
				BaseURL:      opts.url,
				Realm:        opts.realm,
				ClientID:     opts.clientID,
				ClientSecret: opts.clientSecret,
				Username:     opts.username,
				Password:     opts.password,
				Scope:        opts.scope,
			}

			resp, err := keycloak.Login(loginOpts)
			if err != nil {
				return fmt.Errorf("could not perform login: %w", err)
			}

			if cmd.Flag("output").Changed {
				return render(resp, nil)
			} else {
				fmt.Println(resp.AccessToken)
			}
			return nil
		},
	}
	loginCmd.Flags().StringVar(&opts.url, "url", "", "Keycloak base URL")
	loginCmd.Flags().StringVar(&opts.realm, "realm", "", "Keycloak realm name")
	loginCmd.Flags().StringVar(&opts.clientID, "client-id", "", "Keycloak Client ID")
	loginCmd.Flags().StringVar(&opts.clientSecret, "client-secret", "", "Keycloak Client Secret")
	loginCmd.Flags().StringVar(&opts.username, "username", "", "Username (for password grant)")
	loginCmd.Flags().StringVar(&opts.password, "password", "", "Password (for password grant)")
	loginCmd.Flags().StringVar(&opts.scope, "scope", "openid", "Token scope")

	cmd.AddCommand(infoCmd, introspectCmd, loginCmd)
	return cmd
}

func newOIDCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oidc",
		Short: "OIDC integration features",
	}

	opts := &oidcOptions{}

	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Fetch and display OIDC discovery information",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.issuer == "" {
				return fmt.Errorf("--issuer must be specified")
			}

			if outputFormat == "openid" {
				data, err := oidc.FetchDiscoveryRaw(opts.issuer)
				if err != nil {
					return fmt.Errorf("could not fetch discovery document: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			discovery, err := oidc.FetchDiscovery(opts.issuer)
			if err != nil {
				return fmt.Errorf("could not fetch discovery document: %w", err)
			}

			return render(discovery, nil)
		},
	}
	infoCmd.Flags().StringVar(&opts.issuer, "issuer", "", "OIDC issuer URL")

	introspectCmd := &cobra.Command{
		Use:   "introspect [token|-|@file]",
		Short: "Perform server-side token introspection",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.issuer == "" || opts.clientID == "" || opts.clientSecret == "" {
				return fmt.Errorf("--issuer, --client-id, and --client-secret must be specified")
			}

			input := "-"
			if len(args) > 0 {
				input = args[0]
			}

			tokenData, err := resolver.Resolve(input)
			if err != nil {
				return fmt.Errorf("could not resolve token input: %w", err)
			}

			if outputFormat == "json" {
				raw, err := oidc.IntrospectRaw(opts.issuer, opts.clientID, opts.clientSecret, string(tokenData))
				if err != nil {
					return fmt.Errorf("could not perform introspection: %w", err)
				}
				var pretty json.RawMessage = raw
				out, err := json.MarshalIndent(pretty, "", "  ")
				if err != nil {
					fmt.Println(string(raw))
				} else {
					fmt.Println(string(out))
				}
				return nil
			}

			response, err := oidc.Introspect(opts.issuer, opts.clientID, opts.clientSecret, string(tokenData))
			if err != nil {
				return fmt.Errorf("could not perform introspection: %w", err)
			}

			return render(response, nil)
		},
	}
	introspectCmd.Flags().StringVar(&opts.issuer, "issuer", "", "OIDC issuer URL")
	introspectCmd.Flags().StringVar(&opts.clientID, "client-id", "", "OIDC Client ID")
	introspectCmd.Flags().StringVar(&opts.clientSecret, "client-secret", "", "OIDC Client Secret")

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Fetch an access token from an OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.issuer == "" || opts.clientID == "" || opts.clientSecret == "" {
				return fmt.Errorf("--issuer, --client-id, and --client-secret must be specified")
			}

			loginOpts := oidc.LoginOptions{
				Issuer:       opts.issuer,
				ClientID:     opts.clientID,
				ClientSecret: opts.clientSecret,
				Username:     opts.username,
				Password:     opts.password,
				Scope:        opts.scope,
			}

			resp, err := oidc.Login(loginOpts)
			if err != nil {
				return fmt.Errorf("could not perform login: %w", err)
			}

			if cmd.Flag("output").Changed {
				return render(resp, nil)
			} else {
				fmt.Println(resp.AccessToken)
			}
			return nil
		},
	}
	loginCmd.Flags().StringVar(&opts.issuer, "issuer", "", "OIDC issuer URL")
	loginCmd.Flags().StringVar(&opts.clientID, "client-id", "", "OIDC Client ID")
	loginCmd.Flags().StringVar(&opts.clientSecret, "client-secret", "", "OIDC Client Secret")
	loginCmd.Flags().StringVar(&opts.username, "username", "", "Username (for password grant)")
	loginCmd.Flags().StringVar(&opts.password, "password", "", "Password (for password grant)")
	loginCmd.Flags().StringVar(&opts.scope, "scope", "openid", "Token scope")

	cmd.AddCommand(infoCmd, introspectCmd, loginCmd)
	return cmd
}

func newKeygenCmd() *cobra.Command {
	opts := &keygenOptions{}
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new asymmetric key pair (RSA, ECDSA, or EdDSA) in PEM format",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeygen(cmd, args, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.alg, "alg", "a", "rsa", "Algorithm: rsa, ecdsa, or eddsa")
	cmd.Flags().IntVarP(&opts.bits, "bits", "b", 2048, "RSA bit size: 2048, 3072, 4096")
	cmd.Flags().StringVarP(&opts.curve, "curve", "c", "P256", "ECDSA curve: P256, P384, P521")
	cmd.Flags().StringVarP(&opts.file, "file", "f", "", "Save to file (e.g. 'id_rsa' creates 'id_rsa' and 'id_rsa.pub')")

	return cmd
}

func newCreateCmd() *cobra.Command {
	opts := &createOptions{}
	cmd := &cobra.Command{
		Use:     "create",
		Aliases: []string{"sign"},
		Short:   "Create and sign a new JWT",
		Long: `Create and sign a new JWT from scratch.
	Example:
	jwt-tool create --alg HS256 --secret "my-secret" --sub "user123" --exp 1h`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(cmd, args, opts)
		},
	}

	cmd.Flags().StringVar(&opts.alg, "alg", "HS256", "Algorithm: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, EdDSA")
	cmd.Flags().StringVar(&opts.secret, "secret", "", "Symmetric secret for HMAC")
	cmd.Flags().StringVar(&opts.pem, "pem", "", "Path to private key PEM file (@path)")
	cmd.Flags().StringVar(&opts.payload, "payload", "", "Path to JSON file for bulk payload (@path)")
	cmd.Flags().StringSliceVar(&opts.claims, "claim", []string{}, "Custom claims in key=value format (repeatable)")
	cmd.Flags().StringSliceVar(&opts.headers, "header", []string{}, "Custom header fields in key=value format (repeatable)")
	cmd.Flags().StringVar(&opts.exp, "exp", "", "Expiration time (shorthand duration, e.g. 1h, 1d)")
	cmd.Flags().StringVar(&opts.nbf, "nbf", "", "Not before time (shorthand duration, e.g. 1m)")
	cmd.Flags().StringVar(&opts.iat, "iat", "0s", "Issued at time (offset duration, default 0s means now)")
	cmd.Flags().StringVar(&opts.iss, "iss", "", "Issuer claim")
	cmd.Flags().StringVar(&opts.sub, "sub", "", "Subject claim")
	cmd.Flags().StringVar(&opts.aud, "aud", "", "Audience claim")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("jwt-tool version: %s\n", version)
			fmt.Printf("commit: %s\n", commit)
			fmt.Printf("build date: %s\n", date)
		},
	}
}

func newJwksCmd() *cobra.Command {
	opts := &jwksOptions{}
	cmd := &cobra.Command{
		Use:   "jwks [key-input]...",
		Short: "Convert public keys to JSON Web Key Set (JWKS)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runJwks(cmd, args, opts)
		},
	}

	cmd.Flags().StringSliceVar(&opts.kids, "kid", []string{}, "Key ID for each key (repeatable)")
	return cmd
}

func runCreate(cmd *cobra.Command, args []string, cOpts *createOptions) error {
	opts := signer.SignOptions{
		Algorithm: cOpts.alg,
		Claims:    jwt.MapClaims{},
		Header:    make(map[string]interface{}),
	}

	// 1. Resolve Keys
	if cOpts.secret != "" {
		s, err := resolver.Resolve(cOpts.secret)
		if err != nil {
			return fmt.Errorf("could not resolve secret: %w", err)
		}
		opts.Secret = s
	}

	if cOpts.pem != "" {
		p, err := resolver.Resolve(cOpts.pem)
		if err != nil {
			return fmt.Errorf("could not resolve PEM path: %w", err)
		}

		priv, err := keys.ParsePrivateKey(p)
		if err != nil {
			return fmt.Errorf("could not parse private key: %w", err)
		}
		opts.PrivateKey = priv
	}

	// 2. Load Payload File
	if cOpts.payload != "" {
		data, err := resolver.Resolve(cOpts.payload)
		if err != nil {
			return fmt.Errorf("could not resolve payload file: %w", err)
		}
		if err := json.Unmarshal(data, &opts.Claims); err != nil {
			return fmt.Errorf("could not parse payload JSON: %w", err)
		}
	}

	// 3. Apply Shorthand Claims
	now := time.Now()
	if cOpts.exp != "" {
		d, err := time.ParseDuration(cOpts.exp)
		if err != nil {
			return fmt.Errorf("invalid exp duration: %w", err)
		}
		opts.Claims["exp"] = jwt.NewNumericDate(now.Add(d))
	}
	if cOpts.nbf != "" {
		d, err := time.ParseDuration(cOpts.nbf)
		if err != nil {
			return fmt.Errorf("invalid nbf duration: %w", err)
		}
		opts.Claims["nbf"] = jwt.NewNumericDate(now.Add(d))
	}
	if cOpts.iat != "" {
		d, err := time.ParseDuration(cOpts.iat)
		if err != nil {
			return fmt.Errorf("invalid iat duration: %w", err)
		}
		opts.Claims["iat"] = jwt.NewNumericDate(now.Add(d))
	}
	if cOpts.iss != "" {
		opts.Claims["iss"] = cOpts.iss
	}
	if cOpts.sub != "" {
		opts.Claims["sub"] = cOpts.sub
	}
	if cOpts.aud != "" {
		opts.Claims["aud"] = cOpts.aud
	}

	// 4. Parse Individual Claims
	claims, err := signer.ParseKeyValueSlice(cOpts.claims)
	if err != nil {
		return fmt.Errorf("could not parse claims: %w", err)
	}
	for k, v := range claims {
		opts.Claims[k] = v
	}

	// 5. Parse Individual Headers
	headers, err := signer.ParseKeyValueSlice(cOpts.headers)
	if err != nil {
		return fmt.Errorf("could not parse headers: %w", err)
	}
	for k, v := range headers {
		opts.Header[k] = v
	}

	// 6. Security Warnings
	for _, w := range opts.ValidateExpiration() {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	// 7. Sign
	token, err := signer.Sign(opts)
	if err != nil {
		return fmt.Errorf("could not sign token: %w", err)
	}

	// 8. Output
	if cmd.Flag("output").Changed {
		if outputFormat == "json" || outputFormat == "table" {
			info, err := verifier.Decode(token)
			if err != nil {
				return fmt.Errorf("could not decode signed token for output: %w", err)
			}
			return render(info, nil)
		} else {
			fmt.Println(token)
		}
	} else {
		fmt.Println(token)
	}
	return nil
}

func runInspect(cmd *cobra.Command, args []string, iOpts *inspectOptions) error {
	input := "-"
	if len(args) > 0 {
		input = args[0]
	}

	data, err := resolver.Resolve(input)
	if err != nil {
		return fmt.Errorf("could not resolve input: %w", err)
	}

	// Step 1: Always Decode
	info, err := verifier.Decode(string(data))
	if err != nil {
		return fmt.Errorf("could not decode token: %w", err)
	}

	validationFailed := false
	leewayDisplay := "0s"

	// Step 2: Attempt verification if keys are provided
	if iOpts.secret != "" || iOpts.pem != "" || iOpts.jwks != "" {
		opts := verifier.VerifyOptions{
			Algorithms: []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"},
		}

		if iOpts.secret != "" {
			s, err := resolver.Resolve(iOpts.secret)
			if err != nil {
				return fmt.Errorf("could not resolve secret: %w", err)
			}
			opts.Secret = s
		}

		if iOpts.pem != "" {
			p, err := resolver.Resolve(iOpts.pem)
			if err != nil {
				return fmt.Errorf("could not resolve PEM path: %w", err)
			}

			pub, err := keys.ParsePublicKey(p)
			if err != nil {
				return fmt.Errorf("could not parse public key: %w", err)
			}
			opts.PublicKey = pub
		}

		if iOpts.jwks != "" {
			jwks, err := remote.LoadJWKS(iOpts.jwks)
			if err != nil {
				return fmt.Errorf("could not load JWKS: %w", err)
			}
			opts.JWKS = jwks
		}

		if iOpts.leeway != "" {
			d, err := time.ParseDuration(iOpts.leeway)
			if err != nil {
				return fmt.Errorf("could not parse leeway duration: %w", err)
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
	if err := render(info, nil); err != nil {
		return err
	}

	// Step 4: Conditional Exit
	if validationFailed {
		os.Exit(2)
	}
	return nil
}

func runKeygen(cmd *cobra.Command, args []string, kOpts *keygenOptions) error {
	var kp *keygen.KeyPair
	var err error

	switch kOpts.alg {
	case "rsa":
		kp, err = keygen.GenerateRSA(kOpts.bits)
	case "ecdsa":
		kp, err = keygen.GenerateECDSA(kOpts.curve)
	case "eddsa":
		kp, err = keygen.GenerateEdDSA()
	default:
		return fmt.Errorf("unsupported algorithm: %s", kOpts.alg)
	}

	if err != nil {
		return fmt.Errorf("could not generate keys: %w", err)
	}

	if kOpts.file != "" {
		privFile := kOpts.file
		pubFile := kOpts.file + ".pub"

		if err := os.WriteFile(privFile, kp.PrivatePEM, 0600); err != nil {
			return fmt.Errorf("could not write private key: %w", err)
		}
		if err := os.WriteFile(pubFile, kp.PublicPEM, 0644); err != nil {
			return fmt.Errorf("could not write public key: %w", err)
		}
		fmt.Printf("Keys saved to %s and %s\n", privFile, pubFile)
	} else {
		fmt.Print(string(kp.PrivatePEM))
		fmt.Print(string(kp.PublicPEM))
	}
	return nil
}

func render(info interface{}, message *string) error {
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
				return fmt.Errorf("could not format JSON: %w", err)
			}
			fmt.Println(string(out))
		}
		if message != nil {
			fmt.Printf("\n%s\n", *message)
		}
	default:
		out, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("could not format JSON: %w", err)
		}
		fmt.Println(string(out))
	}
	return nil
}

func runJwks(cmd *cobra.Command, args []string, jOpts *jwksOptions) error {
	if len(args) == 0 {
		args = []string{"-"}
	}

	var pubKeys []interface{}
	for _, arg := range args {
		data, err := resolver.Resolve(arg)
		if err != nil {
			return fmt.Errorf("could not resolve input %s: %w", arg, err)
		}

		pub, err := keys.ParsePublicKey(data)
		if err != nil {
			return fmt.Errorf("could not parse public key for %s: %w", arg, err)
		}
		pubKeys = append(pubKeys, pub)
	}

	jwkSet, err := jwks.GenerateJWKS(pubKeys, jOpts.kids)
	if err != nil {
		return fmt.Errorf("could not generate JWKS: %w", err)
	}

	return render(jwkSet, nil)
}
