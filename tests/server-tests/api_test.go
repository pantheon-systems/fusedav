package testserver

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
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

func newrequest(file string, method string, body io.Reader, t *testing.T) (*http.Request, error) {
	req, err := http.NewRequest(method, file, body)
	if err != nil {
		t.Errorf("Error on NewRequest; exiting...")
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

func collectResults(testOutput TestOutput, t *testing.T) {
	// TODO figure out how to collect results
	t.Logf("%v\n", testOutput.result)
}

func testMethod(t *testing.T, testInput TestInput) error {
	var (
		err        error
		req        *http.Request
		testOutput TestOutput
	)

	t.Logf("testMethod: %s %d %s", testInput.method, testInput.expectedStatusCode, testInput.path)
	if testInput.method == "PUT" { // only PUT sends content?
		req, err = newrequest(testInput.path, testInput.method, strings.NewReader(testInput.content), t)
	} else {
		req, err = newrequest(testInput.path, testInput.method, nil, t)
	}
	if err != nil {
		t.Errorf("testMethod: %s, Error: %v", testInput.method, err)
		return err
	}

	for _, pair := range testInput.headers {
		req.Header.Add(pair.key, pair.value)
		t.Logf("testMethod: Headers: method: %s; path: %s; header: %v", testInput.method, testInput.path, req.Header)
	}

	defer collectResults(testOutput, t)
	resp, err := testInput.client.Do(req)
	if err != nil {
		t.Errorf("testMethod: Error on client.Do; method: %s; path: %s; exiting...\n", testInput.method, testInput.path)
		testOutput.err = err
		testOutput.result = ""
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != testInput.expectedStatusCode {
		t.Errorf("testMethod: %s; path: %s; Error, expected Status %d, got %v; body: %v",
			testInput.method, testInput.path, testInput.expectedStatusCode, resp.Status, string(body))
	}

	if testInput.method == "GET" { // Are there other methods which get content. We could genericize
		if err != nil {
			t.Errorf("testMethod: Error on ioutil.ReadAll: %v", err)
			return err
		}

		if testInput.expectedStatusCode != 404 &&
			len(testInput.content) > 0 &&
			string(body) != testInput.content {
			t.Errorf("testMethod: Error, expected content %v, got %v", testInput.content, string(body))
		}
	}

	if testInput.method == "GET" { // Are there other methods which get content. We could genericize
		if err != nil {
			t.Errorf("testMethod: Error on ioutil.ReadAll: %v", err)
			return err
		}

		if testInput.expectedStatusCode != 404 &&
			len(testInput.content) > 0 &&
			string(body) != testInput.content {
			t.Errorf("testMethod: Error, expected content %v, got %v", testInput.content, string(body))
		}
	}

	testOutput.status = resp.Status
	testOutput.statusCode = resp.StatusCode

	return err
}

func TestPaths(t *testing.T) {
	type PathResult struct {
		path       string
		statusCode int
	}

	var testInput TestInput
	var testOutput TestOutput
	var paths []PathResult

	t.Log("TestPaths")

	testInput.client = getClient(t)

	paths = make([]PathResult, 7)
	paths[0].path = getServerPath()
	paths[0].statusCode = 200
	paths[1].path = paths[0].path + "sites/"
	paths[1].statusCode = 405
	// Response might be different if there is a trailing slash after site id
	paths[2].path = paths[1].path + getSiteId()
	paths[2].statusCode = 405
	paths[3].path = paths[2].path + "/environments/"
	paths[3].statusCode = 405
	paths[4].path = paths[3].path + "self/"
	paths[4].statusCode = 404
	paths[5].path = paths[3].path + "dev/"
	paths[5].statusCode = 404
	paths[6].path = paths[5].path + "files/"
	paths[6].statusCode = 404

	testInput.content = "" // content is ignored
	testInput.method = "GET"

	for _, entry := range paths {
		testInput.path = entry.path
		testInput.expectedStatusCode = entry.statusCode
		err := testMethod(t, testInput)
		if err != nil {
			t.Errorf("TestPaths: Error on path %v: %v", testInput.path, err)
		}
		testOutput.result = ""
	}
}

func TestAuxiliaryOps(t *testing.T) {
	var testInput TestInput
	var testOutput TestOutput

	t.Log("TestAuxiliaryFileOps")

	testInput.client = getClient(t)
	filepath := getFilesPath()

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
			t.Errorf("TestAuxiliaryOps: Error on method %s on path %v: %v", method, testInput.path, err)
		}
		testOutput.result = ""
	}
}

func TestBasicFileOps(t *testing.T) {
	var (
		testInput TestInput
		pair      HeaderPair
	)

	t.Log("TestBasicFileOps")

	testInput.client = getClient(t)
	filepath := getFilesPath()

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
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	// Add filename to dirname which was used in MKCOL
	filename := dirname + randstring(8)
	testInput.path = filename
	testInput.method = "PUT"
	testInput.expectedStatusCode = 201
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
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
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}
	// PROPFIND on directory
	testInput.path = dirname
	testInput.method = "PROPFIND"
	testInput.expectedStatusCode = 207
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	// PROPFIND on file
	testInput.path = filename
	testInput.method = "PROPFIND"
	testInput.expectedStatusCode = 207
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	// Clear the headers
	testInput.headers = nil

	testInput.method = "GET"
	testInput.expectedStatusCode = 200
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	// COPY
	// We don't COPY, the OS makes effectively a get/put
	// Kind of a meaningless test
	testInput.method = "GET"
	testInput.expectedStatusCode = 200
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
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
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	// Get the tofile as part of copy to verify
	testInput.method = "GET"
	testInput.expectedStatusCode = 200
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
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
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	// Clear the headers
	testInput.headers = nil

	// Get the newfile to test it has the correct content
	testInput.path = newfile
	testInput.method = "GET"
	testInput.expectedStatusCode = 200
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	// Get the original file. It should get a 404
	testInput.path = filename
	testInput.method = "GET"
	testInput.expectedStatusCode = 404
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}
	// e MOVE

	// DELETE: first, the file we copied to, then the file we moved to,
	// then the directory. The original 'filename' disappeared in the MOVE
	testInput.path = tofile
	testInput.method = "DELETE"
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	testInput.path = newfile
	testInput.method = "DELETE"
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	testInput.path = filename
	testInput.method = "DELETE"
	// returns 204 even if file doesn't exist
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}

	testInput.path = dirname
	testInput.method = "DELETE"
	testInput.expectedStatusCode = 204
	err = testMethod(t, testInput)
	if err != nil {
		t.Errorf("TestBasicFileOps: Error on method %s on path %v: %v", testInput.method, testInput.path, err)
	}
}
