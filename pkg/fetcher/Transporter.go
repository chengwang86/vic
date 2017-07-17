// Copyright 2017 VMware, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fetcher

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"crypto/tls"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/progress"

	"fmt"
	"io"
	"strings"

	"bytes"
	"path"

	"github.com/vmware/vic/pkg/trace"
	"github.com/vmware/vic/pkg/version"
	"golang.org/x/net/context/ctxhttp"
)

const maxTransportAttempts = 5

type Transporter interface {
	Put(ctx context.Context, url *url.URL, body io.Reader, reqHdrs *http.Header, po progress.Output, ids ...string) (http.Header, error)
	Post(ctx context.Context, url *url.URL, body io.Reader, reqHdrs *http.Header, po progress.Output, ids ...string) (http.Header, error)
	Delete(ctx context.Context, url *url.URL, reqHdrs *http.Header, po progress.Output) (http.Header, error)
	Head(ctx context.Context, url *url.URL, reqHdrs *http.Header, po progress.Output) (http.Header, error)
	Get(ctx context.Context, url *url.URL, reqHdrs *http.Header, po progress.Output) (http.Header, io.ReadCloser, error)

	IsStatusUnauthorized() bool
	IsStatusOK() bool
	IsStatusNotFound() bool
	IsStatusAccepted() bool
	IsStatusCreated() bool
	IsStatusNoContent() bool
	IsStatusBadGateway() bool
	IsStatusServiceUnavailable() bool
	IsStatusGatewayTimeout() bool
	Status() int

	ExtractOAuthURL(hdr string, repository *url.URL) (*url.URL, error)
	CompletedUpload(ctx context.Context, digest, uploadUrl string, po progress.Output) error
	UploadLayer(ctx context.Context, digest, uploadUrl string, layer io.Reader, po progress.Output, ids ...string) error
	CancelUpload(ctx context.Context, uploadUrl string, po progress.Output) error
	ObtainUploadUrl(ctx context.Context, registry *url.URL, image string, po progress.Output) (string, error)
	CheckLayerExistence(ctx context.Context, image, digest string, registry *url.URL, po progress.Output) (bool, error)
	MountBlobToRepo(ctx context.Context, registry *url.URL, digest, image, repo string, po progress.Output) (bool, string, error)
}

// URLPusher struct
type URLTransporter struct {
	client *http.Client

	OAuthEndpoint *url.URL

	StatusCode int

	options Options
}

// NewURLFetcher creates a new URLFetcher
func NewURLTransporter(options Options) Transporter {
	/* #nosec */
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: options.InsecureSkipVerify,
			RootCAs:            options.RootCAs,
		},
	}
	client := &http.Client{Transport: tr}

	return &URLTransporter{
		client:  client,
		options: options,
	}
}

func (u *URLTransporter) Put(ctx context.Context, url *url.URL, body io.Reader, reqHdrs *http.Header, po progress.Output, ids ...string) (http.Header, error) {
	hdr, _, err := u.requestWithRetry(ctx, url, body, reqHdrs, "PUT", po)
	return hdr, err
}

func (u *URLTransporter) Post(ctx context.Context, url *url.URL, body io.Reader, reqHdrs *http.Header, po progress.Output, ids ...string) (http.Header, error) {
	hdr, _, err := u.requestWithRetry(ctx, url, body, reqHdrs, "POST", po)
	return hdr, err
}

func (u *URLTransporter) Delete(ctx context.Context, url *url.URL, reqHdrs *http.Header, po progress.Output) (http.Header, error) {
	hdr, _, err := u.requestWithRetry(ctx, url, nil, reqHdrs, "DELETE", po)
	return hdr, err
}

func (u *URLTransporter) Head(ctx context.Context, url *url.URL, reqHdrs *http.Header, po progress.Output) (http.Header, error) {
	hdr, _, err :=  u.requestWithRetry(ctx, url, nil, reqHdrs, "HEAD", po)
	return hdr, err
}

func (u *URLTransporter) Get(ctx context.Context, url *url.URL, reqHdrs *http.Header, po progress.Output) (http.Header, io.ReadCloser, error) {
	return u.requestWithRetry(ctx, url, nil, reqHdrs, "GET", po)
}

func (u *URLTransporter) request(ctx context.Context, url *url.URL, body io.Reader, reqHdrs *http.Header, operation string, po progress.Output) (http.Header, io.ReadCloser, error) {
	req, err := http.NewRequest(operation, url.String(), body)
	if err != nil {
		return nil, nil, err
	}

	u.setBasicAuth(req)

	u.setAuthToken(req)

	u.setUserAgent(req)

	// Add optional request headers
	if reqHdrs != nil {
		for k, values := range *reqHdrs {
			for _, v := range values {
				req.Header.Add(k, v)
			}
		}
	}

	res, err := ctxhttp.Do(ctx, u.client, req)
	if err != nil {
		return nil, nil, err
	}

	defer res.Body.Close()

	log.Debugf("URLTransporter.request() - statuscode: %d, body: %#v, header: %#v", res.StatusCode, res.Body, res.Header)

	u.StatusCode = res.StatusCode

	if u.options.Token == nil && u.IsStatusUnauthorized() {
		// this is the case when fetching the auth token
		hdr := res.Header.Get("www-authenticate")
		if hdr == "" {
			return nil, nil, DoNotRetry{Err: fmt.Errorf("www-authenticate header is missing")}
		}
		return res.Header, nil, nil
	}

	if u.IsStatusUnauthorized() {
		hdr := res.Header.Get("www-authenticate")
		return nil, nil, DoNotRetry{Err: fmt.Errorf("unauthorized: %s", hdr)}
	}

	if u.IsStatusBadGateway() || u.IsStatusGatewayTimeout() || u.IsStatusServiceUnavailable() {
		return nil, nil, RetryOnErr{Err: fmt.Errorf("Network failure: statuscode: %d", res.StatusCode)}
	}

	if u.IsStatusOK() || u.IsStatusCreated() || u.IsStatusNoContent() || u.IsStatusAccepted() || u.IsStatusNotFound() {
		return res.Header, res.Body, nil
	}

	return nil, nil, DoNotRetry{Err: fmt.Errorf("Unexpected http code: %d, URL: %s", u.StatusCode, url)}
}

// pushes content from local cache or stream to a url
func (u *URLTransporter) requestWithRetry(ctx context.Context, url *url.URL, body io.Reader, reqHdrs *http.Header, operation string, po progress.Output, ids ...string) (http.Header, io.ReadCloser, error) {
	defer trace.End(trace.Begin(operation + " " + url.Path))

	// extract ID from ids. Existence of an ID enables progress reporting
	ID := ""
	if len(ids) > 0 {
		ID = ids[0]
	}

	// ctx
	ctx, cancel := context.WithTimeout(context.Background(), u.options.Timeout)
	defer cancel()

	var retries int

	for {
		hdr, bdr, err := u.request(ctx, url, body, reqHdrs, operation, po)
		if err == nil {
			return hdr, bdr, nil
		}

		// If an error was returned because the context was cancelled, we shouldn't retry.
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("cancelled during transporting")
		default:
		}

		retries++
		// give up if we reached maxDownloadAttempts
		if retries == maxTransportAttempts {
			log.Debugf("Hit max download attempts. Failed: %v", err)
			return nil, nil, err
		}

		switch err := err.(type) {
		case DoNotRetry:
			log.Debugf("Error: %s", err.Error())
			return nil, nil, err
		}

		// retry downloading again
		log.Debugf("Transporting failed, retrying: %v", err)

		delay := retries * 5
		ticker := time.NewTicker(time.Second)

	selectLoop:
		for {
			// Do not report progress back if ID is empty
			if ID != "" && po != nil {
				progress.Updatef(po, ID, "Retrying in %d second%s", delay, (map[bool]string{true: "s"})[delay != 1])
			}

			select {
			case <-ticker.C:
				delay--
				if delay == 0 {
					ticker.Stop()
					break selectLoop
				}
			case <-ctx.Done():
				ticker.Stop()
				return nil, nil, fmt.Errorf("cancelled during retry delay")
			}
		}
	}

}

// IsStatusUnauthorized returns true if status code is StatusUnauthorized
func (u *URLTransporter) IsStatusUnauthorized() bool {
	return u.StatusCode == http.StatusUnauthorized
}

// IsStatusOK returns true if status code is StatusOK
func (u *URLTransporter) IsStatusOK() bool {
	return u.StatusCode == http.StatusOK
}

// IsStatusNotFound returns true if status code is StatusNotFound
func (u *URLTransporter) IsStatusNotFound() bool {
	return u.StatusCode == http.StatusNotFound
}

func (u *URLTransporter) IsStatusAccepted() bool {
	return u.StatusCode == http.StatusAccepted
}

func (u *URLTransporter) IsStatusCreated() bool {
	return u.StatusCode == http.StatusCreated
}

func (u *URLTransporter) IsStatusNoContent() bool {
	return u.StatusCode == http.StatusNoContent
}

func (u *URLTransporter) IsStatusBadGateway() bool {
	return u.StatusCode == http.StatusBadGateway
}

func (u *URLTransporter) IsStatusServiceUnavailable() bool {
	return u.StatusCode == http.StatusServiceUnavailable
}

func (u *URLTransporter) IsStatusGatewayTimeout() bool {
	return u.StatusCode == http.StatusGatewayTimeout
}

//func (u *URLPusher) Status() int {
//	return u.StatusCode
//}

func (u *URLTransporter) setUserAgent(req *http.Request) {
	log.Debugf("Setting user-agent to vic/%s", version.Version)
	req.Header.Set("User-Agent", "vic/"+version.Version)
}

func (u *URLTransporter) setBasicAuth(req *http.Request) {
	if u.options.Username != "" && u.options.Password != "" {
		log.Debugf("Setting BasicAuth: %s", u.options.Username)
		req.SetBasicAuth(u.options.Username, u.options.Password)
	}
}

func (u *URLTransporter) setAuthToken(req *http.Request) {
	if u.options.Token != nil {
		req.Header.Set("Authorization", "Bearer "+u.options.Token.Token)
	}
}

// ExtractOAuthURL extracts the OAuth url from the www-authenticate header
func (u *URLTransporter) ExtractOAuthURL(hdr string, repository *url.URL) (*url.URL, error) {

	log.Infof("the hdr in ExtractAuthURL is: %s", hdr)
	tokens := strings.Split(hdr, " ")
	if strings.ToLower(tokens[0]) != "bearer" {
		err := fmt.Errorf("www-authenticate header is corrupted")
		return nil, DoNotRetry{Err: err}
	}
	// example for tokens[1]:
	// bearer realm=\"https://kang.eng.vmware.com/service/token\",
	// service=\"harbor-registry\",
	// scope=\"repository:test/busybox:pull,push repository:test/ubuntu:pull\"
	if len(tokens) == 3 {
		tokens[1] += " " + tokens[2]
	}
	tokens = strings.Split(tokens[1], ",")

	var realm, service, scope string
	for _, token := range tokens {
		if strings.HasPrefix(token, "realm") {
			realm = strings.Trim(token[len("realm="):], "\"")
		}
		if strings.HasPrefix(token, "service") {
			service = strings.Trim(token[len("service="):], "\"")
		}
		if strings.HasPrefix(token, "scope") {
			scope = strings.Trim(token[len("scope="):], "\"")
			scope += ","
			scope += strings.Trim(tokens[len(tokens)-1], "\"")
		}
	}

	if realm == "" {
		err := fmt.Errorf("missing realm in bearer auth challenge")
		return nil, DoNotRetry{Err: err}
	}
	if service == "" {
		err := fmt.Errorf("missing service in bearer auth challenge")
		return nil, DoNotRetry{Err: err}
	}
	// The scope can be empty if we're not getting a token for a specific repo
	if scope == "" && repository != nil {
		err := fmt.Errorf("missing scope in bearer auth challenge")
		return nil, DoNotRetry{Err: err}
	}
	log.Debugf("The service is: %s", service)
	log.Debugf("The realm is: %s", realm)
	log.Debugf("The scope is: %s", scope)
	auth, err := url.Parse(realm)
	if err != nil {
		return nil, err
	}

	q := auth.Query()
	q.Add("service", service)
	if scope != "" {
		q.Add("scope", scope)
	}
	auth.RawQuery = q.Encode()

	return auth, nil
}

// Upload the layer (monolithic upload)
func (u *URLTransporter) UploadLayer(ctx context.Context, digest, uploadUrl string, layer io.Reader, po progress.Output, ids ...string) error {
	defer trace.End(trace.Begin(uploadUrl))

	// PUT /v2/<name>/blobs/uploads/<uuid>?digest=<digest>
	// The uuid is from the `location` header
	// in the response of the first step if successful
	composedUrl, err := url.Parse(uploadUrl)
	if err != nil {
		return fmt.Errorf("failed to parse uploadUrl: %s", err)
	}
	q := composedUrl.Query()
	q.Add("digest", digest)
	composedUrl.RawQuery = q.Encode()

	log.Debugf("The url for UploadLayer is: %s", composedUrl)

	reqHdrs := &http.Header{
		"Content-Type": {"application/octet-stream"},
	}

	id := ""
	if len(ids) > 0 {
		id = ids[0]
	}
	_, err = u.Put(ctx, composedUrl, layer, reqHdrs, po, id)
	if err != nil {
		return fmt.Errorf("failed to upload layer: %s", err)
	}

	if u.IsStatusCreated() {
		log.Infof("The uploadLayer finished successfully")
		return nil
	}

	return fmt.Errorf("unexpected http code during UploadLayer: %d, URL: %s", u.StatusCode, composedUrl)
}

// Cancel the upload process
func (u *URLTransporter) CancelUpload(ctx context.Context, uploadUrl string, po progress.Output) error {
	defer trace.End(trace.Begin(uploadUrl))

	// DELETE /v2/<name>/blobs/uploads/<uuid>
	composedUrl, err := url.Parse(uploadUrl)
	if err != nil {
		return fmt.Errorf("failed to parse uploadUrl: %s", err)
	}

	log.Debugf("The url for CancelUpload is: %s\n ", composedUrl)

	_, err = u.Delete(ctx, composedUrl, nil, po)
	if err != nil {
		return fmt.Errorf("failed to cancel upload: %s", err)
	}

	if u.IsStatusNoContent() {
		log.Infof("The upload process is cancelled successfully")
		return nil
	}

	return fmt.Errorf("unexpected http code during CancelUpload: %d, URL: %s", u.StatusCode, composedUrl)
}

// Notify the registry that the upload process is completed
// Currently this is not used since we only use monolithic upload
// However, if the image layer is too large, chunk upload has to be implemented and this method should be called to complete the process
func (u *URLTransporter) CompletedUpload(ctx context.Context, digest, uploadUrl string, po progress.Output) error {
	defer trace.End(trace.Begin(uploadUrl))

	// PUT /v2/<name>/blob/uploads/<uuid>?digest=<digest>
	composedUrl, err := url.Parse(uploadUrl)
	q := composedUrl.Query()
	q.Add("digest", digest)
	composedUrl.RawQuery = q.Encode()

	log.Debugf("The url for CompletedUpload is: %s", composedUrl)

	reqHdrs := &http.Header{
		"Content-Length": {"0"},
		"Content-Type":   {"application/octet-stream"},
	}
	_, err = u.Put(ctx, composedUrl, bytes.NewReader([]byte("")), reqHdrs, po)
	if err != nil {
		return fmt.Errorf("failed to complete upload: %s", err)
	}

	if u.IsStatusNoContent() {
		log.Infof("The upload process completed successfully")
		return nil
	}

	return fmt.Errorf("unexpected http code during CompletedUpload: %d, URL: %s", u.StatusCode, composedUrl)
}

// Check if a layer exists
func (u *URLTransporter) CheckLayerExistence(ctx context.Context, image, digest string, registry *url.URL, po progress.Output) (bool, error) {
	defer trace.End(trace.Begin(digest))

	// HEAD /v2/<name>/blobs/<digest>
	composedUrl := urlDeepCopy(registry)
	composedUrl.Path = path.Join(registry.Path, image, "blobs", digest)

	log.Debugf("The url for checking layer existence is: %s", composedUrl)

	_, err := u.Head(ctx, composedUrl, nil, po)
	if err != nil {
		return false, fmt.Errorf("failed to check layer existence: %s", err)
	}

	if u.IsStatusOK() {
		log.Debugf("The layer already exists")
		return true, nil
	}

	if u.IsStatusNotFound() {
		log.Infof("The layer does not exist")
		return false, nil
	}
	return false, fmt.Errorf("unexpected http code during CheckLayerExistence: %d, URL: %s", u.StatusCode, composedUrl)
}

// obtain the upload url
func (u *URLTransporter) ObtainUploadUrl(ctx context.Context, registry *url.URL, image string, po progress.Output) (string, error) {
	defer trace.End(trace.Begin(image))

	// POST /v2/<name>/blobs/uploads
	composedUrl := urlDeepCopy(registry)
	composedUrl.Path = path.Join(registry.Path, image, "blobs/uploads/")
	composedUrl.Path += "/"

	log.Debugf("The url for ObtainUploadUrl is: %s", composedUrl)

	hdr, err := u.Post(ctx, composedUrl, nil, nil, po)

	if err != nil {
		return "", err
	}

	// even if the image does not exist (push a new image), we should still be able to get a location for upload
	if u.IsStatusAccepted() {
		log.Debugf("The location is: %s", hdr.Get("Location"))
		return hdr.Get("Location"), nil
	}

	return "", fmt.Errorf("unexpected http code during ObtainUploadUrl: %d, URL: %s", u.StatusCode, composedUrl)
}

func (u *URLTransporter) MountBlobToRepo(ctx context.Context, registry *url.URL, digest, image, repo string, po progress.Output) (bool, string, error) {
	defer trace.End(trace.Begin("image: " + image + ", repo: " + repo))

	// POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repository name>
	// Content-Length: 0
	composedUrl := urlDeepCopy(registry)
	composedUrl.Path = path.Join(registry.Path, image, "blobs/uploads")
	composedUrl.Path += "/"

	q := composedUrl.Query()
	q.Add("mount", digest)
	q.Add("from", repo)
	composedUrl.RawQuery = q.Encode()

	log.Debugf("The url for MountBlobToRepo is: %s\n ", composedUrl)

	reqHdrs := &http.Header{
		"Content-Length": {"0"},
	}

	hdr, err := u.Post(ctx, composedUrl, bytes.NewReader([]byte("")), reqHdrs, po)
	if err != nil {
		return false, "", fmt.Errorf("failed to mount blob to repo: %s", err)
	}

	if u.IsStatusCreated() {
		log.Infof("The blob is already mounted to the repo!")
		return true, "", nil
	}

	if u.IsStatusAccepted() {
		log.Infof("The blob is not mounted to repo '%s' yet", repo)
		log.Infof("The location is: %s", hdr.Get("Location"))
		return false, hdr.Get("Location:"), nil
	}

	return false, "", fmt.Errorf("unexpected http code during ObtainUploadUrl: %d, URL: %s", u.StatusCode, composedUrl)
}

func urlDeepCopy(src *url.URL) *url.URL {
	dest := &url.URL{
		Scheme:     src.Scheme,
		Opaque:     src.Opaque,
		User:       src.User,
		Host:       src.Host,
		Path:       src.Path,
		RawPath:    src.RawPath,
		ForceQuery: src.ForceQuery,
		RawQuery:   src.RawQuery,
		Fragment:   src.Fragment,
	}

	return dest
}

func (u *URLTransporter) Status() int {
	return u.StatusCode
}
