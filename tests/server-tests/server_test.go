package testserver

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type TestConfiguration struct {
	ServerPath string `json:"ServerPath"`
	ServerPort string `json:"ServerPort"`
	BindingId  string `json:"BindingId"`
	SiteId     string `json:"SiteId"`
	Env        string `json:"Env"`
}

var testcfg TestConfiguration

var tlsClientConfig = &tls.Config{
	// RootCAs:            getRootCAs(settings.CACertPath),
	// Certificates:       getBindingCert(configuration.TestCfg),
	// Certificates:
	CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	},
	PreferServerCipherSuites: true,
	// TODO: Add certs to verify against Server
	InsecureSkipVerify: true,
}

func getBindingCert(testcfg TestConfiguration) []tls.Certificate {
	crtpath := "/srv/bindings/" + testcfg.BindingId + "/certs/binding.crt"
	keypath := "/srv/bindings/" + testcfg.BindingId + "/certs/binding.key"
	fmt.Printf("getBindingCert: %s : %s\n", crtpath, keypath)
	cert, err := tls.LoadX509KeyPair(crtpath, keypath)
	if err != nil {
		// handle error
	}
	certs := []tls.Certificate{cert}
	return certs
}

func readConfig() {
	// Read config file and set variables
	file, err := os.Open("test-server-config.json")
	if err != nil {
		// handle error
		fmt.Errorf("readConfig: Error in Open\n")
		panic(err)
	}
	decoder := json.NewDecoder(file)
	testcfg = TestConfiguration{}
	err = decoder.Decode(&testcfg)
	if err != nil {
		// handle error
		fmt.Errorf("readConfig: Error in decoder")
		panic(err)
	}
	fmt.Printf("readConfig: cfg: %v\n", testcfg)
}

func getClient() *http.Client {
	readConfig()
	tlsClientConfig.Certificates = getBindingCert(testcfg)

	transport := &http.Transport{TLSClientConfig: tlsClientConfig}
	client := &http.Client{Transport: transport}
	return client
}

func getFilesPath() string {
	serverpath := getServerPath()
	siteid := testcfg.SiteId
	// bindingid := testcfg.BindingId
	env := testcfg.Env

	filespath := serverpath + "sites/" + siteid + "/environments/" + env + "/files/"
	return filespath
}

func getServerPath() string {
	valhallapath := testcfg.ServerPath
	valhallaport := testcfg.ServerPort
	serverpath := "https://" + valhallapath + ":" + valhallaport + "/"
	return serverpath
}

func getBindingId() string {
	return testcfg.BindingId
}

func getSiteId() string {
	return testcfg.SiteId
}

func getEnv() string {
	return testcfg.Env
}
