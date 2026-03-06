package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	"jwt-tool/internal/formatter"
	"jwt-tool/internal/keygen"
	"jwt-tool/internal/remote"
	"jwt-tool/internal/resolver"
	"jwt-tool/internal/verifier"
	"jwt-tool/pkg/models"
)

var (
	outputFormat string
	secret       string
	pemPath      string
	jwksPath     string
	leeway       string

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
By default, it decodes the provided token (or reads from stdin if no argument is given).`,
		Args: cobra.MaximumNArgs(1),
		Run:  runDecode,
	}

	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "Output format: json or table")

	decodeCmd := &cobra.Command{
		Use:   "decode [token|-|@file]",
		Short: "Decode and print JWT header and claims without verification",
		Args:  cobra.MaximumNArgs(1),
		Run:   runDecode,
	}

	verifyCmd := &cobra.Command{
		Use:   "verify [token|-|@file]",
		Short: "Verify JWT signature and claims",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			input := "-"
			if len(args) > 0 {
				input = args[0]
			}

			data, err := resolver.Resolve(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving token: %v\n", err)
				os.Exit(1)
			}

			opts := verifier.VerifyOptions{
				Algorithms: []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"},
			}

			if secret != "" {
				s, err := resolver.Resolve(secret)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error resolving secret: %v\n", err)
					os.Exit(1)
				}
				opts.Secret = s
			}

			if pemPath != "" {
				p, err := resolver.Resolve(pemPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error resolving PEM: %v\n", err)
					os.Exit(1)
				}
				pub, err := jwt.ParseRSAPublicKeyFromPEM(p)
				if err != nil {
					// Try ECDSA if RSA fails
					pubEC, errEC := jwt.ParseECPublicKeyFromPEM(p)
					if errEC != nil {
						fmt.Fprintf(os.Stderr, "Error parsing PEM (tried RSA and ECDSA): %v\n", err)
						os.Exit(1)
					}
					opts.PublicKey = pubEC
				} else {
					opts.PublicKey = pub
				}
			}

			if jwksPath != "" {
				jwks, err := remote.LoadJWKS(jwksPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error loading JWKS: %v\n", err)
					os.Exit(1)
				}
				opts.JWKS = jwks
			}

			if leeway != "" {
				d, err := time.ParseDuration(leeway)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error parsing leeway: %v\n", err)
					os.Exit(1)
				}
				opts.Leeway = d
			}

			info, err := verifier.Verify(string(data), opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
				os.Exit(2) // Exit 2 for validation errors as per GEMINI.md
			}

			render(info, ptr("✅ Signature and claims are valid."))
		},
	}

	verifyCmd.Flags().StringVar(&secret, "secret", "", "Symmetric secret for HMAC verification")
	verifyCmd.Flags().StringVar(&pemPath, "pem", "", "Path to RSA/ECDSA public key PEM file (@path)")
	verifyCmd.Flags().StringVar(&jwksPath, "jwks", "", "Path or URL to JWKS")
	verifyCmd.Flags().StringVar(&leeway, "leeway", "0s", "Clock skew tolerance (e.g. 60s)")

	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new asymmetric key pair (RSA or ECDSA) in PEM format",
		Run:   runKeygen,
	}

	keygenCmd.Flags().StringVarP(&kgAlg, "alg", "a", "rsa", "Algorithm: rsa or ecdsa")
	keygenCmd.Flags().IntVarP(&kgBits, "bits", "b", 2048, "RSA bit size: 2048, 3072, 4096")
	keygenCmd.Flags().StringVarP(&kgCurve, "curve", "c", "P256", "ECDSA curve: P256, P384, P521")
	keygenCmd.Flags().StringVarP(&kgFile, "file", "f", "", "Save to file (e.g. 'id_rsa' creates 'id_rsa' and 'id_rsa.pub')")

	rootCmd.AddCommand(decodeCmd, verifyCmd, keygenCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runDecode(cmd *cobra.Command, args []string) {
	input := "-"
	if len(args) > 0 {
		input = args[0]
	}

	data, err := resolver.Resolve(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving input: %v\n", err)
		os.Exit(1)
	}

	info, err := verifier.Decode(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding token: %v\n", err)
		os.Exit(1)
	}

	render(info, nil)
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
		fmt.Fprintf(os.Stderr, "Unsupported algorithm: %s\n", kgAlg)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate keys: %v\n", err)
		os.Exit(1)
	}

	if kgFile != "" {
		privFile := kgFile
		pubFile := kgFile + ".pub"

		if err := os.WriteFile(privFile, kp.PrivatePEM, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write private key: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(pubFile, kp.PublicPEM, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write public key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Keys saved to %s and %s\n", privFile, pubFile)
	} else {
		fmt.Print(string(kp.PrivatePEM))
		fmt.Print(string(kp.PublicPEM))
	}
}

func render(info interface{}, message *string) {
	switch outputFormat {
	case "table":
		if tokenInfo, ok := info.(*models.TokenInfo); ok {
			formatter.PrintTokenSummary(tokenInfo)
		} else {
			// Fallback if not TokenInfo (though current commands only use TokenInfo)
			out, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(out))
		}
		if message != nil {
			fmt.Printf("\n%s\n", *message)
		}
	default:
		out, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
	}
}

func ptr(s string) *string {
	return &s
}
