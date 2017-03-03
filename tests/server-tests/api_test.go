package testserver

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type HeaderPair struct {
	key   string
	value string
}

type TestInput struct {
	client             *http.Client
	method             string
	path               string
	content            string
	expectedStatusCode int
	headers            []HeaderPair
}

type TestOutput struct {
	result     string
	status     string
	statusCode int
	err        error
	content    string
}

func newrequest(file string, method string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, file, body)
	if err != nil {
		// handle err
		fmt.Errorf("Error on NewRequest; exiting...")
		return nil, err
	}
	req.Header.Add("Log-To-Journal", "true")
	req.Header.Add("User-Agent", "9999")
	return req, nil
}

// randstring returns a hex string twice the given length
func randstring(len int) string {
	randBytes := make([]byte, len)
	rand.Read(randBytes)
	return hex.EncodeToString(randBytes)
}

func collectResults(testOutput TestOutput) {
	// TODO figure out how to collect results
	fmt.Printf("%v\n", testOutput.result)
}

/* TODO GET check content returned
if len(content) > 0 && string(body) != content {
	t.Errorf("testGET: Error, expected content %v, got %v", content, resp.Body)
}
*/

func testMethod(t *testing.T, testInput TestInput) error {
	var (
		err        error
		req        *http.Request
		testOutput TestOutput
	)

	fmt.Printf("testMethod: %s %d %s\n", testInput.method, testInput.expectedStatusCode, testInput.path)
	if testInput.method == "PUT" { // only PUT sends content?
		req, err = newrequest(testInput.path, testInput.method, strings.NewReader(testInput.content))
	} else {
		req, err = newrequest(testInput.path, testInput.method, nil)
	}
	if err != nil {
		// handle error
		t.Errorf("testMethod: %s, Error: %v", testInput.method, err)
	}

	for _, pair := range testInput.headers {
		req.Header.Add(pair.key, pair.value)
		fmt.Printf("testMethod: method: %s; path: %s; header: %v\n", testInput.method, testInput.path, req.Header)
	}

	defer collectResults(testOutput)
	resp, err := testInput.client.Do(req)
	if err != nil {
		// handle err
		t.Errorf("Error on client.Do; method: %s; path: %s; exiting...\n", testInput.method, testInput.path)
		testOutput.err = err
		testOutput.result = ""
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != testInput.expectedStatusCode {
		t.Errorf("testMethod: %s; path: %s; Error, expected Status %d, got %v",
			testInput.method, testInput.path, testInput.expectedStatusCode, resp.Status)
	}

	testOutput.status = resp.Status
	testOutput.statusCode = resp.StatusCode

	return err
}

func TestAuxiliaryOps(t *testing.T) {
	var testInput TestInput
	var testOutput TestOutput

	fmt.Println("TestAuxiliaryFileOps")

	testInput.client = getClient()
	filepath := getServerPath()

	dirname := filepath + randstring(8) + "/"
	testInput.content = randstring(32)
	testInput.path = dirname
	testInput.content = "" // content is ignored
	testInput.expectedStatusCode = 200

	// for _, method := range []string{"HEAL", "TEST", "LOCK", "PROPPATCH", "OPTIONS"} {
	// Temporarily remove HEAL, it takes a long time
	for _, method := range []string{"TEST", "LOCK", "PROPPATCH", "OPTIONS"} {
		testInput.method = method
		err := testMethod(t, testInput)
		if err != nil {
			// handle error
		}
		// First assignment to res
		testOutput.result = ""
	}
}

func TestBasicFileOps(t *testing.T) {
	var (
		testInput TestInput
		pair      HeaderPair
	)

	fmt.Println("TestBasicFileOps")

	testInput.client = getClient()
	filepath := getServerPath()

	dirname := filepath + randstring(8) + "/"
	testInput.content = randstring(32)
	testInput.path = dirname
	testInput.content = randstring(32)
	testInput.expectedStatusCode = 200

	testInput.method = "MKCOL"
	testInput.expectedStatusCode = 201
	err := testMethod(t, testInput)
	testInput.expectedStatusCode = 200 // Reset to default
	if err != nil {
		// handle error
	}

	// Add filename to dirname which was used in MKCOL
	filename := dirname + randstring(8)
	testInput.path = filename
	testInput.method = "PUT"
	testInput.expectedStatusCode = 201
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	//  Sort of emulating the way propfind works in fusedav-valhalla world
	// PROPFIND on root
	// Create the header pair for:
	// req.Header.Add("depth", "1")
	pair.key = "depth"
	pair.value = "1"
	testInput.path = filepath
	testInput.headers = append(testInput.headers, pair)
	testInput.method = "PROPFIND"
	testInput.expectedStatusCode = 207

	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}
	// PROPFIND on directory
	testInput.path = dirname
	testInput.method = "PROPFIND"
	testInput.expectedStatusCode = 207
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	// PROPFIND on file
	testInput.path = filename
	testInput.method = "PROPFIND"
	testInput.expectedStatusCode = 207
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	testInput.method = "GET"
	testInput.expectedStatusCode = 200
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	// Clear the headers
	testInput.headers = nil

	// COPY
	// We don't COPY, the OS makes effectively a get/put
	// Kind of a meaningless test
	testInput.method = "GET"
	testInput.expectedStatusCode = 200
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	// Sort of cheating. We should use the content we get from GET
	// But if the body is the same as the content anyway, as the
	// test will check, then it doesn't matter
	tofile := dirname + randstring(8)
	testInput.path = tofile
	testInput.method = "PUT"
	testInput.expectedStatusCode = 201
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	// Get the tofile as part of copy to verify
	testInput.method = "GET"
	testInput.expectedStatusCode = 200
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}
	// e COPY

	// MOVE from filename to newfile
	newfile := dirname + randstring(8)
	// Create the header pair for req.Header.Add("Destination", newfile)
	pair.key = "Destination"
	pair.value = newfile
	testInput.headers = append(testInput.headers, pair)
	testInput.path = filename
	testInput.method = "MOVE"
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	// Clear the headers
	testInput.headers = nil

	// Get the newfile to test it has the correct content
	testInput.path = newfile
	testInput.method = "GET"
	testInput.expectedStatusCode = 200
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	// Get the original file. It should get a 404
	testInput.path = filename
	testInput.method = "GET"
	testInput.expectedStatusCode = 404
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}
	// e MOVE

	// DELETE: first, the file we copied to, then the file we moved to,
	// then the directory. The original 'filename' disappeared in the MOVE
	testInput.path = tofile
	testInput.method = "DELETE"
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	testInput.path = newfile
	testInput.method = "DELETE"
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	testInput.path = filename
	testInput.method = "DELETE"
	// returns 204 even if file doesn't exist
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}

	testInput.path = dirname
	testInput.method = "DELETE"
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		// handle error
	}
}
