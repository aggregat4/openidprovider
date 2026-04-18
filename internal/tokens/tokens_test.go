package tokens

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateOpaqueToken(t *testing.T) {
	first, err := GenerateOpaqueToken()
	require.NoError(t, err)
	second, err := GenerateOpaqueToken()
	require.NoError(t, err)

	assert.NotEmpty(t, first)
	assert.NotEmpty(t, second)
	assert.NotEqual(t, first, second)
	assert.NotContains(t, first, "=")
	assert.NotContains(t, first, "+")
	assert.NotContains(t, first, "/")
}

func TestHashOpaqueTokenIsDeterministic(t *testing.T) {
	hashA := HashOpaqueToken("example-token")
	hashB := HashOpaqueToken("example-token")
	hashC := HashOpaqueToken("different-token")

	assert.Equal(t, hashA, hashB)
	assert.NotEqual(t, hashA, hashC)
	assert.Len(t, hashA, 64)
}

func TestTokenHintPrefix(t *testing.T) {
	assert.Equal(t, "short", TokenHintPrefix("short"))

	longToken := strings.Repeat("a", 32)
	assert.Equal(t, strings.Repeat("a", 12), TokenHintPrefix(longToken))
}
