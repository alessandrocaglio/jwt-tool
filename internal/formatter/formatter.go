package formatter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"jwt-tool/pkg/models"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// PrintTokenSummary prints a human-readable table of the JWT header and claims.
func PrintTokenSummary(info *models.TokenInfo) {
	color.New(color.Bold, color.FgCyan).Println("--- JWT HEADER ---")
	printTable(info.Header)

	fmt.Println()

	color.New(color.Bold, color.FgCyan).Println("--- JWT PAYLOAD (CLAIMS) ---")
	printTable(info.Payload)

	fmt.Println()

	color.New(color.Bold, color.FgCyan).Print("SIGNATURE: ")
	if info.Signature != "" {
		color.New(color.FgGreen).Println("Present")
	} else {
		color.New(color.FgRed).Println("Missing")
	}
}

// PrintKeycloakTable prints a human-readable table of the Keycloak discovery document.
func PrintKeycloakTable(discovery *models.KeycloakDiscovery) {
	color.New(color.Bold, color.FgCyan).Println("--- IDENTITY ---")
	fmt.Printf("%s\t%s\n", color.New(color.FgYellow).Sprint("Issuer"), discovery.Issuer)

	fmt.Println()

	color.New(color.Bold, color.FgCyan).Println("--- ENDPOINTS ---")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("	") // pad with tabs
	table.SetNoWhiteSpace(true)

	endpoints := [][]string{
		{"JWKS URI", discovery.JwksURI},
		{"Token", discovery.TokenEndpoint},
		{"Userinfo", discovery.UserinfoEndpoint},
		{"Introspection", discovery.IntrospectionEndpoint},
		{"Authorization", discovery.AuthorizationEndpoint},
	}

	for _, e := range endpoints {
		table.Append([]string{
			color.New(color.FgYellow).Sprint(e[0]),
			e[1],
		})
	}
	table.Render()

	fmt.Println()

	color.New(color.Bold, color.FgCyan).Println("--- CAPABILITIES ---")
	fmt.Printf("%s\t%s\n", color.New(color.FgYellow).Sprint("Grant Types"), strings.Join(discovery.GrantTypesSupported, ", "))
	fmt.Printf("%s\t%s\n", color.New(color.FgYellow).Sprint("Signing Algs"), strings.Join(discovery.IDTokenSigningAlgValuesSupported, ", "))
}

// PrintIntrospectionTable prints a human-readable table of the introspection response.
func PrintIntrospectionTable(response models.IntrospectionResponse) {
	fmt.Print("Status: ")
	if response.IsActive() {
		color.New(color.Bold, color.FgGreen).Println("ACTIVE ✅ (Confirmed by Keycloak)")
	} else {
		color.New(color.Bold, color.FgRed).Println("INACTIVE ❌")
	}

	fmt.Println()

	if !response.IsActive() {
		return
	}

	color.New(color.Bold, color.FgCyan).Println("--- CORE INFO ---")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("	") // pad with tabs
	table.SetNoWhiteSpace(true)

	// Filter common fields to show in Core Info, others will follow or be skipped if redundant
	coreFields := []string{"username", "sub", "client_id", "scope", "token_type"}
	for _, k := range coreFields {
		if val, ok := response[k]; ok {
			table.Append([]string{
				color.New(color.FgYellow).Sprint(k),
				fmt.Sprintf("%v", val),
			})
		}
	}

	// Add exp if present
	if exp, ok := response["exp"]; ok {
		if ts, ok := convertToFloat(exp); ok {
			displayVal := fmt.Sprintf("%.0f (%s)", ts, time.Unix(int64(ts), 0).Format(time.RFC3339))
			table.Append([]string{
				color.New(color.FgYellow).Sprint("exp"),
				displayVal,
			})
		}
	}
	table.Render()

	// Show roles if present (Keycloak specific structures)
	if realmAccess, ok := response["realm_access"].(map[string]interface{}); ok {
		if roles, ok := realmAccess["roles"].([]interface{}); ok {
			fmt.Println()
			color.New(color.Bold, color.FgCyan).Println("--- REALM ACCESS ---")
			roleStrings := make([]string, 0, len(roles))
			for _, r := range roles {
				roleStrings = append(roleStrings, fmt.Sprintf("%v", r))
			}
			fmt.Printf("%s\t%s\n", color.New(color.FgYellow).Sprint("Roles"), strings.Join(roleStrings, ", "))
		}
	}

	if resourceAccess, ok := response["resource_access"].(map[string]interface{}); ok {
		fmt.Println()
		color.New(color.Bold, color.FgCyan).Println("--- RESOURCE ACCESS ---")
		for client, access := range resourceAccess {
			if accessMap, ok := access.(map[string]interface{}); ok {
				if roles, ok := accessMap["roles"].([]interface{}); ok {
					roleStrings := make([]string, 0, len(roles))
					for _, r := range roles {
						roleStrings = append(roleStrings, fmt.Sprintf("%v", r))
					}
					fmt.Printf("%s\t%s\n", color.New(color.FgYellow).Sprint(client), strings.Join(roleStrings, ", "))
				}
			}
		}
	}
}

// PrintLoginTable prints a human-readable table of the login response.
func PrintLoginTable(resp *models.TokenResponse) {
	color.New(color.Bold, color.FgGreen).Println("Login: SUCCESS ✅")
	fmt.Println()

	color.New(color.Bold, color.FgCyan).Println("--- TOKENS ---")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("	")
	table.SetNoWhiteSpace(true)

	// Helper to truncate long tokens
	truncate := func(s string) string {
		if len(s) > 40 {
			return s[:40] + "..."
		}
		return s
	}

	table.Append([]string{color.New(color.FgYellow).Sprint("Access Token"), truncate(resp.AccessToken)})
	if resp.RefreshToken != "" {
		table.Append([]string{color.New(color.FgYellow).Sprint("Refresh Token"), truncate(resp.RefreshToken)})
	}
	table.Append([]string{color.New(color.FgYellow).Sprint("Expires In"), fmt.Sprintf("%ds", resp.ExpiresIn)})
	table.Append([]string{color.New(color.FgYellow).Sprint("Token Type"), resp.TokenType})
	table.Append([]string{color.New(color.FgYellow).Sprint("Scope"), resp.Scope})

	table.Render()
}

func printTable(data map[string]interface{}) {
	table := tablewriter.NewWriter(os.Stdout)
	//table.SetHeader([]string{"Key", "Value"})
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("	") // pad with tabs
	table.SetNoWhiteSpace(true)

	// Sort keys for consistent output
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val := data[k]
		displayVal := fmt.Sprintf("%v", val)

		// Convert timestamps to human-readable strings
		if isTimestampKey(k) {
			if ts, ok := convertToFloat(val); ok {
				displayVal = fmt.Sprintf("%.0f (%s)", ts, time.Unix(int64(ts), 0).Format(time.RFC3339))
			}
		}

		table.Append([]string{
			color.New(color.FgYellow).Sprint(k),
			displayVal,
		})
	}
	table.Render()
}

func isTimestampKey(key string) bool {
	switch key {
	case "exp", "iat", "nbf", "auth_time", "updated_at":
		return true
	default:
		return false
	}
}

func convertToFloat(val interface{}) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case int64:
		return float64(v), true
	case int:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}
