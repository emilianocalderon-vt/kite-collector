package sqlite

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptFile(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.db")
	enc := filepath.Join(dir, "encrypted.db")
	dec := filepath.Join(dir, "decrypted.db")

	content := []byte("SQLite format 3\000 -- test database content here")
	require.NoError(t, os.WriteFile(plain, content, 0600))

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	require.NoError(t, EncryptFile(plain, enc, key))

	// Encrypted file should differ from plaintext.
	encData, err := os.ReadFile(enc)
	require.NoError(t, err)
	assert.NotEqual(t, content, encData)

	require.NoError(t, DecryptFile(enc, dec, key))

	decData, err := os.ReadFile(dec)
	require.NoError(t, err)
	assert.Equal(t, content, decData)
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.db")
	enc := filepath.Join(dir, "encrypted.db")
	dec := filepath.Join(dir, "decrypted.db")

	require.NoError(t, os.WriteFile(plain, []byte("secret data"), 0600))

	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)

	require.NoError(t, EncryptFile(plain, enc, key1))
	err := DecryptFile(enc, dec, key2)
	assert.Error(t, err, "decryption with wrong key should fail")
}

func TestIsEncrypted(t *testing.T) {
	dir := t.TempDir()

	// Non-existent file.
	enc, err := IsEncrypted(filepath.Join(dir, "missing.db"))
	require.NoError(t, err)
	assert.False(t, enc)

	// Raw SQLite file.
	sqlitePath := filepath.Join(dir, "raw.db")
	require.NoError(t, os.WriteFile(sqlitePath, []byte("SQLite format 3\000rest of file"), 0600))
	enc, err = IsEncrypted(sqlitePath)
	require.NoError(t, err)
	assert.False(t, enc)

	// Encrypted file.
	encPath := filepath.Join(dir, "encrypted.db")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	require.NoError(t, EncryptFile(sqlitePath, encPath, key))
	enc, err = IsEncrypted(encPath)
	require.NoError(t, err)
	assert.True(t, enc)
}
