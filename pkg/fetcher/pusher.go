// Copyright 2016-2017 VMware, Inc. All Rights Reserved.
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

	"crypto/tls"

	log "github.com/Sirupsen/logrus"

	"io"

	"fmt"
	"strings"

	"bytes"
	"path"
	"strconv"

	"github.com/vmware/vic/pkg/trace"
	"github.com/vmware/vic/pkg/version"
	"golang.org/x/net/context/ctxhttp"
)

// Pusher interface
type Pusher interface {
	Push(ctx context.Context, url *url.URL, body io.Reader, reqHdrs *http.Header, operation string) (http.Header, error)
	IsStatusUnauthorized() bool
	IsStatusOK() bool
	IsStatusNotFound() bool
	IsStatusAccepted() bool
	IsStatusCreated() bool
	Status() int

	CompletedUpload(ctx context.Context, digest, uploadUrl string, registry *url.URL) error
	UploadLayer(ctx context.Context, digest, uploadUrl string, registry *url.URL, layer []byte) error
	CancelUpload(ctx context.Context, uploadUrl string, registry *url.URL) error
	ObtainUploadUrl(ctx context.Context, registry *url.URL, image string) (string, error)
	CheckLayerExistence(ctx context.Context, image, digest string, registry *url.URL) (bool, error)
	MountBlobToRepo(ctx context.Context, registry *url.URL, digest, image, repo string) (bool, string, error)
}

// URLPusher struct
type URLPusher struct {
	client *http.Client

	OAuthEndpoint *url.URL

	StatusCode int

	options Options
}

// NewURLFetcher creates a new URLFetcher
func NewURLPusher(options Options) Pusher {
	/* #nosec */
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: options.InsecureSkipVerify,
			RootCAs:            options.RootCAs,
		},
	}
	client := &http.Client{Transport: tr}

	return &URLPusher{
		client:  client,
		options: options,
	}
}

// Push pushes content from local cache or stream to a url
//	hdrs is optional.
func (u *URLPusher) Push(ctx context.Context, url *url.URL, body io.Reader, reqHdrs *http.Header, operation string) (http.Header, error) {
	defer trace.End(trace.Begin(operation + " " + url.Path))

	req, err := http.NewRequest(operation, url.String(), body)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	defer res.Body.Close()

	u.StatusCode = res.StatusCode

	if u.options.Token == nil && u.IsStatusUnauthorized() {
		hdr := res.Header.Get("www-authenticate")
		if hdr == "" {
			return nil, fmt.Errorf("www-authenticate header is missing")
		}
		u.OAuthEndpoint, err = u.ExtractOAuthURL(hdr, url)
		if err != nil {
			return nil, err
		}
		return nil, DoNotRetry{Err: fmt.Errorf("Authentication required")}
	}

	if u.IsStatusUnauthorized() {
		hdr := res.Header.Get("www-authenticate")
		return nil, fmt.Errorf("unauthorized due to %s", hdr)
	}

	log.Debugf("URLPusher.push() - body: %#v, header: %#v", res.Body, res.Header)
	return res.Header, nil
}

// IsStatusUnauthorized returns true if status code is StatusUnauthorized
func (u *URLPusher) IsStatusUnauthorized() bool {
	return u.StatusCode == http.StatusUnauthorized
}

// IsStatusOK returns true if status code is StatusOK
func (u *URLPusher) IsStatusOK() bool {
	return u.StatusCode == http.StatusOK
}

// IsStatusNotFound returns true if status code is StatusNotFound
func (u *URLPusher) IsStatusNotFound() bool {
	return u.StatusCode == http.StatusNotFound
}

func (u *URLPusher) IsStatusAccepted() bool {
	return u.StatusCode == http.StatusAccepted
}

func (u *URLPusher) IsStatusCreated() bool {
	return u.StatusCode == http.StatusCreated
}

func (u *URLPusher) Status() int {
	return u.StatusCode
}

func (u *URLPusher) setUserAgent(req *http.Request) {
	log.Debugf("Setting user-agent to vic/%s", version.Version)
	req.Header.Set("User-Agent", "vic/"+version.Version)
}

func (u *URLPusher) setBasicAuth(req *http.Request) {
	if u.options.Username != "" && u.options.Password != "" {
		log.Debugf("Setting BasicAuth: %s", u.options.Username)
		req.SetBasicAuth(u.options.Username, u.options.Password)
	}
}

func (u *URLPusher) setAuthToken(req *http.Request) {
	if u.options.Token != nil {
		req.Header.Set("Authorization", "Bearer "+u.options.Token.Token)
	}
}

// ExtractOAuthURL extracts the OAuth url from the www-authenticate header
func (u *URLPusher) ExtractOAuthURL(hdr string, repository *url.URL) (*url.URL, error) {

	log.Infof("the hdr in ExtractAuthURL is: %s", hdr)
	tokens := strings.Split(hdr, " ")
	if len(tokens) != 2 || strings.ToLower(tokens[0]) != "bearer" {
		err := fmt.Errorf("www-authenticate header is corrupted")
		return nil, DoNotRetry{Err: err}
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
	log.Infof("The service is: %s", service)
	log.Infof("The realm is: %s", realm)
	log.Infof("The scope is: %s", scope)
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

// upload the layer (monolithic upload)
// PUT /v2/<name>/blobs/uploads/<uuid>?digest=<digest>; this uuid is from the `location` header
// in the response of the first step if successful
func (u *URLPusher) UploadLayer(ctx context.Context, digest, uploadUrl string, registry *url.URL, layer []byte) error {
	defer trace.End(trace.Begin(uploadUrl))

	composedUrl := urlDeepCopy(registry)
	uploadUrl = fmt.Sprintf("%s?digest=%s", uploadUrl, digest)
	composedUrl.Path = path.Join(registry.Path, uploadUrl)

	log.Infof("The url for UploadLayer is: %s\n ", composedUrl)

	reqHdrs := &http.Header{
		"Content-Length": {strconv.Itoa(len(layer))},
		"Content-Type":   {"application/octet-stream"},
	}

	hdr, err := u.Push(ctx, composedUrl, bytes.NewReader(layer), reqHdrs, "PUT")
	if err != nil {
		return fmt.Errorf("failed to upload layer: %s", err)
	}

	log.Infof("UploadLayer res.Header: %+v", hdr)

	if u.IsStatusAccepted() {
		log.Infof("The upload layer finishes successfully")
		return nil
	}

	return fmt.Errorf("unexpected http code during UploadLayer: %d, URL: %s", u.Status(), composedUrl)
}

// DELETE /v2/<name>/blobs/uploads/<uuid>
func (u *URLPusher) CancelUpload(ctx context.Context, uploadUrl string, registry *url.URL) error {
	defer trace.End(trace.Begin(uploadUrl))

	composedUrl := urlDeepCopy(registry)
	composedUrl.Path = path.Join(registry.Path, uploadUrl)

	log.Infof("The url for CancelUpload is: %s\n ", composedUrl)

	hdr, err := u.Push(ctx, composedUrl, nil, nil, "DELETE")
	if err != nil {
		return fmt.Errorf("failed to cancel upload: %s", err)
	}

	log.Infof("CancelUpload res.Header: %+v", hdr)

	if u.IsStatusOK() {
		log.Infof("The upload process is cancelled successfully")
		return nil
	}

	return fmt.Errorf("unexpected http code during CancelUpload: %d, URL: %s", u.Status(), composedUrl)
}

func (u *URLPusher) CompletedUpload(ctx context.Context, digest, uploadUrl string, registry *url.URL) error {
	defer trace.End(trace.Begin(uploadUrl))
	// PUT /v2/<name>/blob/uploads/<uuid>?digest=<digest>
	// From docker's documentation: if all chunks have already been uploaded,
	// a PUT request with a digest parameter and zero-length body
	// may be sent to complete and validated the upload.

	composedUrl := urlDeepCopy(registry)
	uploadUrl = fmt.Sprintf("%s?digest=%s", uploadUrl, digest)
	composedUrl.Path = path.Join(registry.Path, uploadUrl)

	log.Infof("The url for CompletedUpload is: %s\n ", composedUrl)

	hdr, err := u.Push(ctx, composedUrl, nil, nil, "PUT")
	if err != nil {
		return fmt.Errorf("failed to complete upload: %s", err)
	}

	log.Infof("CompletedUpload res.Header: %+v", hdr)

	if u.IsStatusCreated() {
		log.Infof("The upload process completed successfully")
		return nil
	}

	return fmt.Errorf("unexpected http code during CompletedUpload: %d, URL: %s", u.Status(), composedUrl)
}

// HEAD /v2/<name>/blobs/<digest>
func (u *URLPusher) CheckLayerExistence(ctx context.Context, image, digest string, registry *url.URL) (bool, error) {
	defer trace.End(trace.Begin(digest))

	composedUrl := urlDeepCopy(registry)
	composedUrl.Path = path.Join(registry.Path, image, "blobs", digest)

	log.Infof("The url for checking layer existence is: %s\n ", composedUrl)

	hdr, err := u.Push(ctx, composedUrl, nil, nil, "HEAD")
	if err != nil {
		return false, fmt.Errorf("failed to check layer existence: %s", err)
	}

	if u.IsStatusUnauthorized() {
		return false, fmt.Errorf("unauthorized during CheckLayerExistence: %s", hdr.Get("www-authenticate"))
	}

	if u.IsStatusOK() {
		log.Infof("The layer already exists; no need to upload")
		return true, nil
	}

	if u.IsStatusNotFound() {
		log.Infof("The layer does not exist")
		return false, nil
	}
	return false, fmt.Errorf("unexpected http code during CheckLayerExistence: %d, URL: %s", u.Status(), composedUrl)
}

// obtain the upload url
// POST /v2/<name>/blobs/uploads
func (u *URLPusher) ObtainUploadUrl(ctx context.Context, registry *url.URL, image string) (string, error) {
	defer trace.End(trace.Begin(image))

	composedUrl := urlDeepCopy(registry)
	composedUrl.Path = path.Join(registry.Path, image, "blobs/uploads")

	log.Infof("The url for ObtainUploadUrl is: %s\n ", composedUrl)

	// obtain the upload url
	// POST /v2/<name>/blobs/uploads
	hdr, err := u.Push(ctx, composedUrl, nil, nil, "POST")
	if err != nil {
		return "", err
	}

	log.Infof("ObtainUploadURL res.Header: %+v", hdr)

	// TODO: what if the image does not exist in the registry previously? Will the POST request return 404 Not Found?
	if u.IsStatusAccepted() {
		log.Infof("The location is: %s", hdr.Get("Location"))
		return hdr.Get("Location:"), nil
	}

	return "", fmt.Errorf("unexpected http code during ObtainUploadUrl: %d, URL: %s", u.Status(), composedUrl)
}

func (u *URLPusher) MountBlobToRepo(ctx context.Context, registry *url.URL, digest, image, repo string) (bool, string, error) {
	defer trace.End(trace.Begin("image: " + image + ", repo: " + repo))

	composedUrl := urlDeepCopy(registry)
	suffix := fmt.Sprintf("blobs/uploads?mount=%s&from=%s", digest, repo)
	composedUrl.Path = path.Join(registry.Path, image, suffix)

	log.Infof("The url for MountBlobToRepo is: %s\n ", composedUrl)

	// POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repository name>
	// Content-Length: 0
	reqHdrs := &http.Header{
		"Content-Length": {"0"},
	}

	hdr, err := u.Push(ctx, composedUrl, nil, reqHdrs, "POST")
	if err != nil {
		return false, "", fmt.Errorf("failed to mount blob to repo: %s", err)
	}

	log.Infof("MountBlobToRepo res.Header: %+v", hdr)

	if u.IsStatusCreated() {
		log.Infof("The blob is already mounted to the repo!")
		return true, "", nil
	}

	if u.IsStatusAccepted() {
		log.Infof("The blob is not mounted to repo '%s' yet", repo)
		log.Infof("The location is: %s", hdr.Get("Location"))
		return false, hdr.Get("Location:"), nil
	}

	return false, "", fmt.Errorf("unexpected http code during ObtainUploadUrl: %d, URL: %s", u.Status(), composedUrl)
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
