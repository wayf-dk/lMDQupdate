package main

import (
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wayf-dk/gosaml"
)

/*
Fetch metadata
Split into MDQ files in new folder
Create a subfolder for each feed
Verify files
Move symlink to new folder
Remove old folder

health check
log of updates
Run as daemon
Take updates intervals as environment
Take location as environment
Take folder basename and location as environment

Make the code testable
Fetch json file for discovery service
*/

// Default config values
var config = map[string]string{
	// example for metadataurl: hubpub::https://metadata.wayf.dk/wayf-metadata.xml::3c9a81a80e9032f888ba3cc7ac564364c38f283e;;hubpub2::https://metadata.wayf.dk/wayf-metadata.xml::3c9a81a80e9032f888ba3cc7ac564364c38f283e
	// Each feed tuple consist of 'name::url::sslmodulushash' . Each tuple is seperated by ';;'
	"metadataurl":          "",
	"discoveryurl":         "https://phph.wayf.dk/DS/wayf-interfed.discofeed.jsgz",
	"basefolder":           "",
	"datafoldernameformat": "lmdqdata_",
	"symlinkfolder":        "lmdqdata",
	// Use ws-federation.xsd to validate because its include both saml-schema-metadata-2.0.xsd and other metadata schemas
	"metadataschemapath": "vendor/github.com/wayf-dk/gosaml/schemas/ws-federation.xsd",
}

type feedtuple struct {
	name           string
	url            string
	sslmodulushash string
}

var feeds []feedtuple

// Set initial config values
func initConfig() {
	// Overwrite default config with config from environment variables
	// All variable MUST have a value but we can not verify the variable content
	for k, _ := range config {
		if os.Getenv(k) != "" {
			config[k] = os.Getenv(k)
		}

		log.Printf("Config: %s = %s", k, config[k])
	}
	for k, v := range config {
		if v == "" {
			log.Fatalf("ERROR: Missing config for '%s'", k)
		}
	}

	// Populate the feed array
	for _, feed := range strings.Split(config["metadataurl"], ";;") {
		fau := strings.Split(feed, "::")
		if len(fau) == 3 {
			feedname := fau[0]
			url := fau[1]
			SSLmodulusHash := fau[2]
			if feedname == "" || url == "" || SSLmodulusHash == "" {
				log.Fatalf("Feed, url and hash string wrong '%s'", fau)
			} else {
				feeds = append(feeds, feedtuple{feedname, url, SSLmodulusHash})
			}
		} else {
			log.Fatalf("Wrong feed format '%s'", feed)
		}
	}
}

// Create a new set of subfolders for MDQ metadata at the basefolder location.
// It's named based on dataFolderNameFormat and a unix timestamp
// It's a fatal error if the folder creation fails
func createDateTimeFolder(baseFolder string, dataFolderNameFormat string) (foldername string, err error) {
	timenow := time.Now()
	foldername = fmt.Sprintf("%s/%s%d", baseFolder, dataFolderNameFormat, timenow.Unix())
	err = os.Mkdir(foldername, 0755)
	if err != nil {
		return "", fmt.Errorf("Create new datafolder %s failed", err)
	}
	return
}

// Create or move the symlink pointer to the folder with the active metadata set
func symlinkMetadataFolder(symlinkFolder string, newRealFolder string) (err error) {
	var oldRealFolder string
	createSymlink := true

	oldRealFolder, err = filepath.EvalSymlinks(symlinkFolder)
	// Symlink exists and shall not change
	if err == nil && oldRealFolder == newRealFolder {
		createSymlink = false
	}

	if createSymlink {
		// Remove symlink before create a new one.
		// Only remove if exists.
		if _, err = os.Stat(symlinkFolder); err == nil {
			err = os.Remove(symlinkFolder)
			if err != nil {
				return
			}
		}
		// Create new symlink
		err = os.Symlink(newRealFolder, symlinkFolder)
		if err != nil {
			return
		}
	}

	// Only cleanup if there exists a old folder. If old folder = nil then RemoveAll return no error
	err = os.RemoveAll(oldRealFolder)
	return
}

func validateMetadata(metadata []byte, MetadataSchemaPath string, SSLmodulusHash string) (err error) {
	dom := gosaml.NewXp(metadata)
	_, err = dom.SchemaValidate(MetadataSchemaPath)
	if err != nil {
		return
	}

	certificate := dom.Query(nil, "(/md:EntitiesDescriptor|/md:EntityDescriptor)/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
	if len(certificate) != 1 {
		err = fmt.Errorf("Metadata not signed")
		return
	}
	keyname, key, err := gosaml.PublicKeyInfo(dom.NodeGetContent(certificate[0]))

	if err != nil {
		return
	}
	ok := dom.VerifySignature(nil, key)
	if ok != nil || keyname != SSLmodulusHash {
		return fmt.Errorf("Signature check failed. Signature %s, %s = %s", ok, keyname, SSLmodulusHash)
	}
	return
}

// Fetch one metadata set. Call it for each metadata set.
// Get - insecure Get if https is used, doesn't matter for metadata as we check the signature anyway
func fetchData(url string) (data []byte, err error) {
	var resp *http.Response
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
	}

	resp, err = client.Get(url)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Status code: %d (%s)", resp.StatusCode, url)
	}
	data, err = ioutil.ReadAll(resp.Body)
	return
}

func createDiscoServiceFile(data []byte, baseFolder string, feedName string, fileName string) (err error) {
	dataPath := fmt.Sprintf("%s/%s", baseFolder, feedName)

	// Create subdir for feed
	err = os.Mkdir(dataPath, 0755)
	if err != nil {
		log.Fatalf("ERROR: subdir '%s': %s", dataPath, err)
	}

	fd, err := os.Create(fmt.Sprintf("%s/%s", dataPath, fileName))
	if fd != nil {
		defer fd.Close()
	}
	if err != nil {
		return
	}
	_, err = fd.Write(data)
	return
}

// Write a metadata snipet in a file. The filename be the entityname or a sha1 of that.
// Dirpath is based on the parsed feed
func createEntityFile(entityMetadata []byte, dirpath string, filename string) (err error) {
	fd, err := os.Create(fmt.Sprintf("%s/{sha1}%s", dirpath, filename))
	if fd != nil {
		defer fd.Close()
	}
	if err != nil {
		return
	}
	_, err = fd.Write(entityMetadata)
	return
}

func createMDQFiles(metadata []byte, baseFolder string, feedName string) (err error) {
	var indextargets []string = []string{
		"./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location",
		// "./md:SPSSODescriptor/md:AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
	}
	metadataPath := fmt.Sprintf("%s/%s", baseFolder, feedName)

	// Create subdir for feed
	err = os.Mkdir(metadataPath, 0755)
	if err != nil {
		log.Fatalf("ERROR: subdir '%s': %s", metadataPath, err)
	}

	dom := gosaml.NewXp(metadata)
	entities := dom.Query(nil, "(/md:EntityDescriptor|/md:EntitiesDescriptor/md:EntityDescriptor)")
	for _, entity := range entities {
		// Create new dom with metadata sniptet for this entity
		entityMetadata := gosaml.NewXpFromNode(entity).X2s()

		// Find the entityID and write metadata snipet to hash of entityID as filename
		entityID := dom.Query1(entity, "@entityID")
		// if seen[entityID] {
		// 	log.Printf("lMDQ duplicate entityID: %s", entityID)
		// 	continue
		// }
		entityIDHashName := hex.EncodeToString(gosaml.Hash(crypto.SHA1, entityID))
		err = createEntityFile([]byte(entityMetadata), metadataPath, entityIDHashName)
		if err != nil {
			return
		}

		// Find the location and write metadata snipet to hash of location as filename
		for _, target := range indextargets {
			locations := dom.Query(entity, target)
			for _, location := range locations {
				locatetionHashName := hex.EncodeToString(gosaml.Hash(crypto.SHA1, dom.NodeGetContent(location)))
				err = createEntityFile([]byte(entityMetadata), metadataPath, locatetionHashName)
				if err != nil {
					return
				}
			}
		}
	}
	return
}

func main() {
	var discoServiceData []byte
	var body []byte
	var err error

	initConfig()
	folderName, err := createDateTimeFolder(config["basefolder"], config["datafoldernameformat"])
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}

	// fmt.Printf("fau: %v\n url: %s\n feedname: %s\n", fau, url, feedname)
	for _, feed := range feeds {
		body, err = fetchData(feed.url)
		if err != nil {
			log.Fatalf("ERROR: %s", err)
		}
		if err = validateMetadata(body, config["metadataschemapath"], feed.sslmodulushash); err != nil {
			log.Fatalf("ERROR: %s", err)
		}
		err = createMDQFiles(body, folderName, feed.name)
		if err != nil {
			log.Fatalf("ERROR: %s", err)
		}
	}
	// Fetch discovery service file. Hardcode subdir name to discoservice
	if discoServiceData, err = fetchData(config["discoveryurl"]); err != nil {
		log.Fatalf("ERROR: %s", err)
	}

	if err = createDiscoServiceFile(discoServiceData, folderName, "discofeed", "wayf-interfed.discofeed.jsgz"); err != nil {
		log.Fatalf("ERROR: %s", err)
	}

	// When all works then move the symlink pointer and remove the old folder
	err = symlinkMetadataFolder(config["basefolder"]+"/"+config["symlinkfolder"], folderName)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
    log.Printf("OK: lMDQ update succesfull. New folder is %s", folderName)
}
