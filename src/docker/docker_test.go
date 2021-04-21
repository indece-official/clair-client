package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseImageIdentifiers(t *testing.T) {
	path := "myorga/myimage:v1.0.0"

	identifier, err := ParseImageIdentifiers(path, "docker.mydomain.com")

	assert.NoError(t, err)
	assert.NotNil(t, identifier)
	assert.Equal(t, "myorga/myimage", identifier.Repository)
	assert.Equal(t, "v1.0.0", identifier.Tag)
}

func TestParseImageIdentifiersNoTag(t *testing.T) {
	path := "myorga/myimage"

	identifier, err := ParseImageIdentifiers(path, "docker.mydomain.com")

	assert.NoError(t, err)
	assert.NotNil(t, identifier)
	assert.Equal(t, "myorga/myimage", identifier.Repository)
	assert.Equal(t, "latest", identifier.Tag)
}

func TestParseImageIdentifiersSha256Tag(t *testing.T) {
	path := "myorga/myimage:sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"

	identifier, err := ParseImageIdentifiers(path, "docker.mydomain.com")

	assert.NoError(t, err)
	assert.NotNil(t, identifier)
	assert.Equal(t, "myorga/myimage", identifier.Repository)
	assert.Equal(t, "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4", identifier.Tag)
}

func TestParseImageIdentifiersWithDomain(t *testing.T) {
	path := "test.domain.com/myorga/myimage:v1.0.0"

	identifier, err := ParseImageIdentifiers(path, "test.domain.com")

	assert.NoError(t, err)
	assert.NotNil(t, identifier)
	assert.Equal(t, "myorga/myimage", identifier.Repository)
	assert.Equal(t, "v1.0.0", identifier.Tag)
}

func TestParseImageIdentifiersWithHttpURL(t *testing.T) {
	path := "http://test.domain.com/myorga/myimage:v1.0.0"

	identifier, err := ParseImageIdentifiers(path, "test.domain.com")

	assert.NoError(t, err)
	assert.NotNil(t, identifier)
	assert.Equal(t, "myorga/myimage", identifier.Repository)
	assert.Equal(t, "v1.0.0", identifier.Tag)
}

func TestParseImageIdentifiersWithHttpsURL(t *testing.T) {
	path := "https://test.DOMAIN.com//myorga/myimage:v1.0.0"

	identifier, err := ParseImageIdentifiers(path, "http://test.domain.com//")

	assert.NoError(t, err)
	assert.NotNil(t, identifier)
	assert.Equal(t, "myorga/myimage", identifier.Repository)
	assert.Equal(t, "v1.0.0", identifier.Tag)
}
