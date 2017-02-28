package testserver

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

func newrequest(file string, method string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, file, body)
	if err != nil {
		// handle err
		err = fmt.Errorf("Error on NewRequest; exiting...")
		return nil, err
	}
	req.Header.Add("Log-To-Journal", "true")
	req.Header.Add("User-Agent", "9999")
	return req, nil
}

func newcopyrequest(file1, file2 string, method string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, file1, body)
	if err != nil {
		// handle err
		err = fmt.Errorf("Error on NewRequest; exiting...")
		return nil, err
	}
	req.Header.Add("Log-To-Journal", "true")
	req.Header.Add("User-Agent", "9999")
	req.Header.Add("Destination", file2)
	return req, nil
}

// randstring returns a hex string twice the given length
func randstring(len int) string {
	randBytes := make([]byte, len)
	rand.Read(randBytes)
	return hex.EncodeToString(randBytes)
}

func testMKCOL(t *testing.T, client *http.Client, dirname string) (string, error) {
	fmt.Printf("testMKCOL: %s\n", dirname)
	req, err := newrequest(dirname, "MKCOL", nil)
	if err != nil {
		// handle error
		t.Errorf("testMKCOL: Error: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// handle err
		fmt.Printf("Error on client.Do; err: %v, exiting ...\n", err)
		t.Errorf("Error on client.Do; exiting...\n")
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Errorf("testMKCOL: Error, expected Status 201, got %v", resp.Status)
	}

	res := "testMKCOL: " + resp.Status
	return res, nil
}

func testPROPFIND(t *testing.T, client *http.Client, filename string) (string, error) {
	fmt.Printf("testPROPFIND: %s\n", filename)
	req, err := newrequest(filename, "PROPFIND", nil)
	if err != nil {
		// handle error
		t.Errorf("testMKCOL: Error: %v", t)
	}
	req.Header.Add("depth", "1")

	resp, err := client.Do(req)
	if err != nil {
		// handle err
		fmt.Printf("Error on client.Do; err: %v, exiting ...\n", err)
		t.Errorf("Error on client.Do; exiting...\n")
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 207 {
		t.Errorf("testPROPFIND: Error, expected Status 207, got %v", resp.Status)
	}

	// TODO: Would like to get xml contents and parse
	fmt.Printf("testPROPFIND: response: %v\n", resp)

	res := "testPROPFIND: " + resp.Status
	return res, nil
}

func testPUT(t *testing.T, client *http.Client, filename string, content string) (string, error) {
	fmt.Printf("testPUT: %s\n", filename)
	req, err := newrequest(filename, "PUT", strings.NewReader(content))
	if err != nil {
		// handle error
		t.Errorf("testPUT: Error: %v", t)
	}

	resp, err := client.Do(req)
	if err != nil {
		// handle error
		t.Errorf("testPUT: Error: %v", t)
	}

	if err != nil {
		// handle err
		fmt.Printf("Error on client.Do; err: %v, exiting ...\n", err)
		t.Errorf("Error on client.Do; exiting...\n")
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Errorf("testPUT: Error, expected Status 201, got %v", resp.Status)
	}

	res := "testPUT: " + resp.Status
	return res, nil
}

func testMOVE(t *testing.T, client *http.Client, fromfile string, tofile string) (string, error) {
	fmt.Printf("testMOVE: %s\n", fromfile)
	req, err := newrequest(fromfile, "MOVE", nil)
	if err != nil {
		// handle error
		t.Errorf("testMOVE: Error: %v", t)
	}
	// 'to' file goes in header as 'Destination'
	req.Header.Add("Destination", tofile)

	resp, err := client.Do(req)
	if err != nil {
		// handle err
		fmt.Printf("Error on client.Do; err: %v, exiting ...\n", err)
		t.Errorf("Error on client.Do; exiting...\n")
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		t.Errorf("testMOVE: Error, expected Status 204, got %v", resp.Status)
	}

	res := "testMOVE: " + resp.Status
	return res, nil
}

func testGET(t *testing.T, client *http.Client, filename string, content string) (string, error) {
	fmt.Printf("testGET: %s\n", filename)
	req, err := newrequest(filename, "GET", nil)
	if err != nil {
		// handle error
		t.Errorf("testGET: Error: %v", t)
	}

	resp, err := client.Do(req)
	if err != nil {
		// handle err
		fmt.Printf("Error on client.Do; err: %v, exiting ...\n", err)
		t.Errorf("Error on client.Do; exiting...\n")
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		t.Errorf("testGET: Error on ioutil.ReadAll: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("testGET: Error, expected Status 200, got %v", resp.Status)
	}

	if len(content) > 0 && string(body) != content {
		t.Errorf("testGET: Error, expected content %v, got %v", content, resp.Body)
	}

	res := "testGET: " + resp.Status
	return res, nil
}

func testDELETE(t *testing.T, client *http.Client, filename string) (string, error) {
	fmt.Printf("testDELETE: %s\n", filename)
	req, err := newrequest(filename, "DELETE", nil)
	if err != nil {
		// handle error
		t.Errorf("testDELETE: Error: %v", t)
	}

	resp, err := client.Do(req)
	if err != nil {
		// handle err
		fmt.Printf("Error on client.Do; err: %v, exiting ...\n", err)
		t.Errorf("Error on client.Do; exiting...\n")
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		t.Errorf("testDELETE: Error, expected Status 200, got %v", resp.Status)
	}

	res := "testDELETE: " + resp.Status
	return res, nil
}

func TestAPI(t *testing.T) {
	var res string

	fmt.Println("TestAPI")

	client := getClient()
	filepath := getServerPath()

	dirname := filepath + randstring(8) + "/"
	content := randstring(32)

	res1, err := testMKCOL(t, client, dirname)
	if err != nil {
		// handle error
	}
	// First assignment to res
	res = res + res1

	// Add filename to dirname which was used in MKCOL
	filename := dirname + randstring(8)
	res1, err = testPUT(t, client, filename, content)
	if err != nil {
		// handle error
	}
	// Next assignment to res
	res = res + " : " + res1

	//  Sort of emulating the way propfind works in fusedav-valhalla world
	// PROPFIND on root
	res1, err = testPROPFIND(t, client, filepath)
	if err != nil {
		// handle error
	}
	// Next assignment to res
	res = res + " : " + res1

	// PROPFIND on directory
	res1, err = testPROPFIND(t, client, dirname)
	if err != nil {
		// handle error
	}
	// Next assignment to res
	res = res + " : " + res1

	// PROPFIND on file
	res1, err = testPROPFIND(t, client, filename)
	if err != nil {
		// handle error
	}
	// Next assignment to res
	res = res + " : " + res1

	res1, err = testGET(t, client, filename, content)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1

	// COPY
	// We don't COPY, the OS makes effectively a get/put
	// Kind of a meaningless test
	res1, err = testGET(t, client, filename, content)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1

	// Sort of cheating. We should use the content we get from GET
	// But if the body is the same as the content anyway, as the
	// test will check, then it doesn't matter
	tofile := dirname + randstring(8)
	res1, err = testPUT(t, client, tofile, content)
	if err != nil {
		// handle error
	}
	// Next assignment to res
	res = res + " : " + res1

	// Get the tofile as part of copy to verify
	res1, err = testGET(t, client, tofile, content)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1
	// e COPY

	// MOVE
	newfile := dirname + randstring(8)
	res1, err = testMOVE(t, client, filename, newfile)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1

	// Get the newfile to test it has the correct content
	res1, err = testGET(t, client, newfile, content)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1

	// Get the original file. It should get a 404
	res1, err = testGET(t, client, filename, content)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1
	// e MOVE

	// DELETE: first, the file we copied to, then the file we moved to,
	// then the directory. The original 'filename' disappeared in the MOVE
	res1, err = testDELETE(t, client, tofile)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1

	res1, err = testDELETE(t, client, newfile)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1

	res1, err = testDELETE(t, client, dirname)
	if err != nil {
		// handle error
	}
	res = res + " : " + res1

	collectResults(res)
}
