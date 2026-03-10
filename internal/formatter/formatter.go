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
