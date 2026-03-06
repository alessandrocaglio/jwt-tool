package resolver

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// Resolve takes an input string and returns its content as a byte slice.
// If the input is "-", it reads from stdin.
// If it starts with "@", it reads from the specified file path.
// Otherwise, it returns the input string itself as bytes.
func Resolve(input string) ([]byte, error) {
	var data []byte
	var err error

	if input == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read from stdin: %w", err)
		}
	} else if strings.HasPrefix(input, "@") {
		filePath := strings.TrimPrefix(input, "@")
		data, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
		}
	} else {
		data = []byte(input)
	}

	return bytes.TrimSpace(data), nil
}
