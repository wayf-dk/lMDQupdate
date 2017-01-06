package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/wayf-dk/gosaml"
)

var SSLmodulusHash string = "3c9a81a80e9032f888ba3cc7ac564364c38f283e"
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
	err := validateMetadata(metadata[:30], "src/github.com/wayf-dk/gosaml/schemas/saml-schema-protocol-2.0.xsd", SSLmodulusHash)
	if err.Error() != "Document validation error -1" {
		t.Error("Document not validation failed")
	}
}

func TestValidateMetadataNotValidSchema(t *testing.T) {
	err := validateMetadata(metadata, "src/github.com/wayf-dk/gosaml/schemas/saml-schema-protocol-2.0.xsd", SSLmodulusHash)
	if err.Error() != "Document validation error 1845" {
		t.Error("Schema not validation failed")
	}
}

func TestValidateMetadataWrongDigest(t *testing.T) {
	dom := gosaml.NewXp(metadata)
	dom.QueryDashP(nil, "/./ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue[1]", "+dPr0aJZ4IF5ovxAe7Uss+xBu0UNdtgoHq9CppyH2Vs=", nil)
	metadata2 := []byte(dom.Pp())
	err := validateMetadata(metadata2, "src/github.com/wayf-dk/gosaml/schemas/saml-schema-metadata-2.0.xsd", SSLmodulusHash)
	if err.Error() != "Signature check failed. Signature digest mismatch, 3c9a81a80e9032f888ba3cc7ac564364c38f283e = 3c9a81a80e9032f888ba3cc7ac564364c38f283e" {
		t.Errorf("Wrong digest failed '%s'", err)
	}
}

func TestValidateMetadata(t *testing.T) {
	err := validateMetadata(metadata, "src/github.com/wayf-dk/gosaml/schemas/saml-schema-metadata-2.0.xsd", SSLmodulusHash)
	if err != nil {
		t.Errorf("Document not valided '%s'", err)
	}
}
