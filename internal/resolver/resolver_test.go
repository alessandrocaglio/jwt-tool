package resolver

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Run("Direct String", func(t *testing.T) {
		input := "my-raw-string"
		got, err := Resolve(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != input {
			t.Errorf("got %s, want %s", string(got), input)
		}
	})

	t.Run("File Path (@path)", func(t *testing.T) {
		content := "file-content"
		tmpfile, err := os.CreateTemp("", "resolve-test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}

		got, err := Resolve("@" + tmpfile.Name())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != content {
			t.Errorf("got %s, want %s", string(got), content)
		}
	})

	t.Run("Stdin (-)", func(t *testing.T) {
		content := "stdin-content"
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = r

		go func() {
			defer w.Close()
			if _, err := io.Copy(w, bytes.NewBufferString(content)); err != nil {
				// In a goroutine we can't call t.Errorf easily without coordination,
				// but for a test writer we can just panic or ignore if we really don't care.
				// However, to satisfy the linter and be robust:
				return
			}
		}()

		got, err := Resolve("-")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != content {
			t.Errorf("got %s, want %s", string(got), content)
		}
	})

	t.Run("Non-existent File", func(t *testing.T) {
		_, err := Resolve("@non-existent-file-path")
		if err == nil {
			t.Error("expected error for non-existent file, got nil")
		}
	})
}
