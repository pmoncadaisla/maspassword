package internal_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAESImport verifies the Zero-Knowledge invariant:
// the server must NEVER import crypto/aes or crypto/cipher.
func TestNoAESImport(t *testing.T) {
	forbidden := []string{"crypto/aes", "crypto/cipher"}

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Skip test files
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)

		for _, pkg := range forbidden {
			if strings.Contains(content, `"`+pkg+`"`) {
				t.Errorf("file %s imports forbidden package %q — Zero-Knowledge violation!", path, pkg)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking directory: %v", err)
	}
}
