package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/wayf-dk/gosaml"
)

var SSLmodulusHash string = "3c9a81a80e9032f888ba3cc7ac564364c38f283e"

// var schemaPath string
const schemaPath string = "vendor/github.com/wayf-dk/gosaml/schemas/ws-federation.xsd"
const wrongSchema string = "vendor/github.com/wayf-dk/gosaml/schemas/saml-schema-protocol-2.0.xsd"

var metadata []byte

// =======================================================
func TestMain(m *testing.M) {
	var err error
	metadata, err = ioutil.ReadFile("metadata_test.xml")
	if err != nil {
		return
	}
	os.Exit(m.Run())
}

func TestValidateMetadataNotValidDocument(t *testing.T) {
	err := validateMetadata(metadata[:30], schemaPath, SSLmodulusHash)
	if err.Error() != "Document validation error -1" {
		t.Errorf("Document not validation failed '%s'", err)
	}
}

func TestValidateMetadataWrongSchema(t *testing.T) {
	// Validate with a wrong schema to verify that it fails
	err := validateMetadata(metadata, wrongSchema, SSLmodulusHash)
	// If no error or the wrong error then fail
	if err == nil || err.Error() != "Document validation error 1845" {
		t.Errorf("Wrong schema validation failed '%s'", err)
	}
}

func TestValidateMetadataWrongDigest(t *testing.T) {
	dom := gosaml.NewXp(metadata)
	dom.QueryDashP(nil, "/./ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue[1]", "+dPr0aJZ4IF5ovxAe7Uss+xBu0UNdtgoHq9CppyH2Vs=", nil)
	metadata2 := []byte(dom.Pp())
	err := validateMetadata(metadata2, schemaPath, SSLmodulusHash)
	if err.Error() != "Signature check failed. Signature digest mismatch, 3c9a81a80e9032f888ba3cc7ac564364c38f283e = 3c9a81a80e9032f888ba3cc7ac564364c38f283e" {
		t.Errorf("Wrong digest failed '%s'", err)
	}
}

// Catch all validation test
func TestValidateMetadata(t *testing.T) {
	err := validateMetadata(metadata, schemaPath, SSLmodulusHash)
	if err != nil {
		t.Errorf("Document not valided '%s'", err)
	}
}
