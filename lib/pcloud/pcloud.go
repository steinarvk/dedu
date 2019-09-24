package pcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"

	pb "github.com/steinarvk/dedu/gen/dedupb"
)

var (
	AlreadyExists = errors.New("File already exists")
)

const (
	apiBaseURL = "https://api.pcloud.com/"
)

type Storage struct {
	creds  *pb.PcloudCredentials
	folder string
	client *http.Client
}

func (s *Storage) Connection(ctx context.Context) *Storage {
	client := s.createClient(ctx)
	return &Storage{
		creds:  s.creds,
		folder: s.folder,
		client: client,
	}
}

func (s *Storage) Put(ctx context.Context, name string, data []byte) error {
	_, err := s.ChecksumFileSha1(ctx, filepath.Join(s.folder, name))
	if !os.IsNotExist(err) {
		return AlreadyExists
	}

	args := map[string]string{
		"path":      s.folder,
		"filename":  name,
		"nopartial": "1",
	}
	t0 := time.Now()
	err = s.getOrPost(ctx, "uploadfile", args, nil, true, data)
	dur := time.Since(t0)
	if err != nil {
		return err
	}
	speed := float64(len(data)) / dur.Seconds()
	logrus.WithFields(logrus.Fields{
		"size":     len(data),
		"duration": dur,
		"speed":    speed,
	}).Infof("Uploaded file %q", name)
	return nil
}

type getFilelinkResponse struct {
	Path  string   `json:"path"`
	Hosts []string `json:"hosts"`
}

func (s *Storage) Get(ctx context.Context, name string) ([]byte, error) {
	args := map[string]string{"path": filepath.Join(s.folder, name)}
	resp := getFilelinkResponse{}
	if err := s.call(ctx, "getfilelink", args, &resp); err != nil {
		return nil, err
	}
	if len(resp.Hosts) < 1 {
		return nil, fmt.Errorf("No hosts returned")
	}
	host := resp.Hosts[0]

	u := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   resp.Path,
	}

	httpClient := s.createClient(ctx)

	t0 := time.Now()
	logrus.WithFields(logrus.Fields{
		"host":     host,
		"filename": name,
	}).Infof("Downloading from pcloud")

	var finalErr error
	var bodyData []byte
	defer func() {
		dur := time.Since(t0)
		if finalErr != nil {
			logrus.WithFields(logrus.Fields{
				"host":     host,
				"filename": name,
				"duration": dur,
				"status":   "failure",
			}).Errorf("Download from pcloud failed: %v", finalErr)
		} else {
			speed := float64(len(bodyData)) / dur.Seconds()
			logrus.WithFields(logrus.Fields{
				"host":     host,
				"filename": name,
				"size":     len(bodyData),
				"speed":    speed,
				"duration": dur,
				"status":   "ok",
			}).Infof("Download from pcloud successful")
		}
	}()

	httpResp, err := httpClient.Get(u.String())
	if err != nil {
		finalErr = err
		return nil, fmt.Errorf("Download error (from %q): %v", host, err)
	}
	defer httpResp.Body.Close()
	bodyData, err = ioutil.ReadAll(httpResp.Body)
	if err != nil {
		finalErr = err
		return nil, fmt.Errorf("Download error (from %q): %v", host, err)
	}

	return bodyData, nil
}

func (s *Storage) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, fmt.Errorf("Not implemented")
}

type metadataResponse struct {
	Size int64 `json:"size"`
}

type checksumResponse struct {
	Sha1     string           `json:"sha1"`
	Md5      string           `json:"md5"`
	Metadata metadataResponse `json:"metadata"`
}

func (s *Storage) ChecksumFileSha1(ctx context.Context, path string) (string, error) {
	resp := checksumResponse{}
	args := map[string]string{"path": path}
	if err := s.call(ctx, "checksumfile", args, &resp); err != nil {
		return "", err
	}
	return resp.Sha1, nil
}

func (s *Storage) formatURL(endpoint string, args map[string]string) string {
	v := url.Values{}
	v.Set("username", s.creds.Username)
	v.Set("password", s.creds.Password)
	if args != nil {
		for key, val := range args {
			v.Set(key, val)
		}
	}
	u := url.URL{
		Scheme:   "https",
		Host:     "api.pcloud.com",
		Path:     endpoint,
		RawQuery: v.Encode(),
	}
	return u.String()
}

type pcloudBasicResult struct {
	Result int    `json:"result"`
	Error  string `json:"error"`
}

type pcloudError struct {
	result  int
	message string
}

func makePcloudError(pce pcloudError) error {
	if pce.result == 2009 {
		return os.ErrNotExist
	}
	return pce
}

func (e pcloudError) Error() string {
	return fmt.Sprintf("pcloud error %d: %s", e.result, e.message)
}

type httpError struct {
	status int
	data   []byte
}

func (e httpError) Error() string {
	return fmt.Sprintf("HTTP error %d", e.status)
}

func (s *Storage) call(ctx context.Context, endpoint string, args map[string]string, dest interface{}) error {
	return s.getOrPost(ctx, endpoint, args, dest, false, nil)
}

func (s *Storage) getOrPost(ctx context.Context, endpoint string, args map[string]string, dest interface{}, post bool, postData []byte) error {
	logrus.WithFields(logrus.Fields{
		"endpoint": endpoint,
		"post":     post,
	}).Infof("Calling pcloud %q", endpoint)
	t0 := time.Now()
	var status string
	defer func() {
		dur := time.Since(t0)
		logrus.WithFields(logrus.Fields{
			"endpoint": endpoint,
			"post":     post,
			"duration": dur,
			"status":   status,
		}).Infof("Called pcloud %q", endpoint)
	}()

	var client *http.Client = s.client
	if client == nil {
		client = s.createClient(ctx)
	}
	u := s.formatURL(endpoint, args)

	var resp *http.Response
	var err error
	if post {
		buf := bytes.NewReader(postData)
		var req *http.Request
		req, err = http.NewRequest("POST", u, buf)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(postData)))
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err = client.Do(req)
	} else {
		resp, err = client.Get(u)
	}
	if err != nil {
		return fmt.Errorf("pcloud call %q failed: %v", endpoint, err)
	}
	status = resp.Status
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Call to pcloud %q failed: Read error: %v", endpoint, err)
	}

	logrus.Debugf("pcloud response: %s", string(data))

	basicResponse := pcloudBasicResult{}
	if err := json.Unmarshal(data, &basicResponse); err != nil {
		return fmt.Errorf("Call to pcloud %q failed: JSON decode error: %v", endpoint, err)
	}
	if basicResponse.Result != 0 {
		return makePcloudError(pcloudError{result: basicResponse.Result, message: basicResponse.Error})
	}

	ok := resp.StatusCode >= 200 && resp.StatusCode < 299
	if !ok {
		return httpError{status: resp.StatusCode, data: data}
	}

	if dest != nil {
		if err := json.Unmarshal(data, dest); err != nil {
			return fmt.Errorf("Call to pcloud %q failed: JSON decode error: %v", endpoint, err)
		}
	}

	return nil
}

func (s *Storage) Ping(ctx context.Context) error {
	return s.call(ctx, "userinfo", nil, nil)
}

func (s *Storage) checkFolderExists(ctx context.Context, path string) error {
	return s.call(ctx, "listfolder", map[string]string{"path": path, "nofiles": "1", "noshares": "1"}, nil)
}

func (s *Storage) createClient(ctx context.Context) *http.Client {
	return &http.Client{}
}

func New(ctx context.Context, creds *pb.PcloudCredentials, folder string) (*Storage, error) {
	store := &Storage{creds: creds, folder: folder}

	conn := store.Connection(ctx)

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("Unable to connect to pcloud: %v", err)
	}

	if folder != "" {
		if err := conn.checkFolderExists(ctx, folder); err != nil {
			return nil, fmt.Errorf("Failed to ensure that pcloud folder %q exists: %v", folder, err)
		}
	}

	return store, nil
}
