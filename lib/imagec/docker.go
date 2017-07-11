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

package imagec

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"

	log "github.com/Sirupsen/logrus"

	ddigest "github.com/docker/distribution/digest"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	dlayer "github.com/docker/docker/layer"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/progress"
	"github.com/docker/docker/reference"
	"github.com/docker/libtrust"

	"bytes"

	"bufio"
	"compress/gzip"

	urlfetcher "github.com/vmware/vic/pkg/fetcher"
	registryutils "github.com/vmware/vic/pkg/registry"
	"github.com/vmware/vic/pkg/trace"
)

const (
	// DigestSHA256EmptyTar is the canonical sha256 digest of empty tar file -
	// (1024 NULL bytes)
	DigestSHA256EmptyTar = string(dlayer.DigestSHA256EmptyTar)

	compressionBufSize = 32768
)

// FSLayer is a container struct for BlobSums defined in an image manifest
type FSLayer struct {
	// BlobSum is the tarsum of the referenced filesystem image layer
	BlobSum string `json:"blobSum"`
}

// History is a container struct for V1Compatibility defined in an image manifest
type History struct {
	V1Compatibility string `json:"v1Compatibility"`
}

// Manifest represents the Docker Manifest file
type Manifest struct {
	Name     string    `json:"name"`
	Tag      string    `json:"tag"`
	Digest   string    `json:"digest,omitempty"`
	FSLayers []FSLayer `json:"fsLayers"`
	History  []History `json:"history"`
	// ignoring signatures
}

// LearnRegistryURL returns the registry URL after making sure that it responds to queries
func LearnRegistryURL(options *Options) (string, error) {
	defer trace.End(trace.Begin(options.Registry))

	log.Debugf("Trying https scheme for %#v", options)

	registry, err := registryutils.Reachable(options.Registry, "https", options.Username, options.Password, options.RegistryCAs, options.Timeout, options.InsecureSkipVerify)

	if err != nil && options.InsecureAllowHTTP {
		// try https without verification
		log.Debugf("Trying https without verification, last error: %+v", err)
		registry, err = registryutils.Reachable(options.Registry, "https", options.Username, options.Password, options.RegistryCAs, options.Timeout, true)
		if err == nil {
			// Success, set InsecureSkipVerify to true
			options.InsecureSkipVerify = true
		} else {
			// try http
			log.Debugf("Falling back to http")
			registry, err = registryutils.Reachable(options.Registry, "http", options.Username, options.Password, options.RegistryCAs, options.Timeout, options.InsecureSkipVerify)
		}
	}

	return registry, err
}

// LearnAuthURL returns the URL of the OAuth endpoint
func LearnAuthURL(options Options) (*url.URL, error) {
	defer trace.End(trace.Begin(options.Reference.String()))

	url, err := url.Parse(options.Registry)
	if err != nil {
		return nil, err
	}

	tagOrDigest := tagOrDigest(options.Reference, options.Tag)
	url.Path = path.Join(url.Path, options.Image, "manifests", tagOrDigest)
	log.Debugf("URL: %s", url)

	fetcher := urlfetcher.NewURLFetcher(urlfetcher.Options{
		Timeout:            options.Timeout,
		Username:           options.Username,
		Password:           options.Password,
		InsecureSkipVerify: options.InsecureSkipVerify,
		RootCAs:            options.RegistryCAs,
	})

	// We expect docker registry to return a 401 to us - with a WWW-Authenticate header
	// We parse that header and learn the OAuth endpoint to fetch OAuth token.
	hdr, err := fetcher.Head(url)
	if err == nil && fetcher.IsStatusUnauthorized() {
		return fetcher.ExtractOAuthURL(hdr.Get("www-authenticate"), url)
	}

	// Private registry returned the manifest directly as auth option is optional.
	// https://github.com/docker/distribution/blob/master/docs/configuration.md#auth
	if err == nil && options.Registry != DefaultDockerURL && fetcher.IsStatusOK() {
		log.Debugf("%s does not support OAuth", url)
		return nil, nil
	}

	// Do we even have the image on that registry
	if err != nil && fetcher.IsStatusNotFound() {
		err = fmt.Errorf("image not found")
		return nil, urlfetcher.ImageNotFoundError{Err: err}
	}

	return nil, fmt.Errorf("%s returned an unexpected response: %s", url, err)
}

// FetchToken fetches the OAuth token from OAuth endpoint
func FetchToken(ctx context.Context, options Options, url *url.URL, progressOutput progress.Output) (*urlfetcher.Token, error) {
	defer trace.End(trace.Begin(url.String()))

	log.Debugf("URL: %s", url)

	fetcher := urlfetcher.NewURLFetcher(urlfetcher.Options{
		Timeout:            options.Timeout,
		Username:           options.Username,
		Password:           options.Password,
		InsecureSkipVerify: options.InsecureSkipVerify,
		RootCAs:            options.RegistryCAs,
	})

	token, err := fetcher.FetchAuthToken(url)
	if err != nil {
		err := fmt.Errorf("FetchToken (%s) failed: %s", url, err)
		log.Error(err)
		return nil, err
	}

	return token, nil
}

// FetchImageBlob fetches the image blob
func FetchImageBlob(ctx context.Context, options Options, image *ImageWithMeta, progressOutput progress.Output) (string, error) {
	defer trace.End(trace.Begin(options.Image + "/" + image.Layer.BlobSum))

	id := image.ID
	layer := image.Layer.BlobSum
	meta := image.Meta
	diffID := ""

	url, err := url.Parse(options.Registry)
	if err != nil {
		return diffID, err
	}
	url.Path = path.Join(url.Path, options.Image, "blobs", layer)

	log.Debugf("URL: %s\n ", url)

	fetcher := urlfetcher.NewURLFetcher(urlfetcher.Options{
		Timeout:            options.Timeout,
		Username:           options.Username,
		Password:           options.Password,
		Token:              options.Token,
		InsecureSkipVerify: options.InsecureSkipVerify,
		RootCAs:            options.RegistryCAs,
	})

	// ctx
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	imageFileName, err := fetcher.Fetch(ctx, url, nil, true, progressOutput, image.String())
	if err != nil {
		return diffID, err
	}

	// Cleanup function for the error case
	defer func() {
		if err != nil {
			os.Remove(imageFileName)
		}
	}()

	// Open the file so that we can use it as a io.Reader for sha256 calculation
	imageFile, err := os.Open(string(imageFileName))
	if err != nil {
		return diffID, err
	}
	defer imageFile.Close()

	// blobSum is the sha of the compressed layer
	blobSum := sha256.New()

	// diffIDSum is the sha of the uncompressed layer
	diffIDSum := sha256.New()

	// blobTr is an io.TeeReader that writes bytes to blobSum that it reads from imageFile
	// see https://golang.org/pkg/io/#TeeReader
	blobTr := io.TeeReader(imageFile, blobSum)

	progress.Update(progressOutput, image.String(), "Verifying Checksum")
	decompressedTar, err := archive.DecompressStream(blobTr)
	if err != nil {
		return diffID, err
	}

	// Copy bytes from decompressed layer into diffIDSum to calculate diffID
	_, cerr := io.Copy(diffIDSum, decompressedTar)
	if cerr != nil {
		return diffID, cerr
	}

	bs := fmt.Sprintf("sha256:%x", blobSum.Sum(nil))
	if bs != layer {
		return diffID, fmt.Errorf("Failed to validate layer checksum. Expected %s got %s", layer, bs)
	}

	diffID = fmt.Sprintf("sha256:%x", diffIDSum.Sum(nil))

	// this isn't an empty layer, so we need to calculate the size
	if diffID != string(DigestSHA256EmptyTar) {
		var layerSize int64

		// seek to the beginning of the file
		imageFile.Seek(0, 0)

		// recreate the decompressed tar Reader
		decompressedTar, err := archive.DecompressStream(imageFile)
		if err != nil {
			return "", err
		}

		// get a tar reader for access to the files in the archive
		tr := tar.NewReader(decompressedTar)

		// iterate through tar headers to get file sizes
		for {
			tarHeader, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", err
			}
			layerSize += tarHeader.Size
		}

		image.Size = layerSize
	}

	log.Infof("diffID for layer %s: %s", id, diffID)

	// Ensure the parent directory exists
	destination := path.Join(DestinationDirectory(options), id)
	err = os.MkdirAll(destination, 0755) /* #nosec */
	if err != nil {
		return diffID, err
	}

	// Move(rename) the temporary file to its final destination
	err = os.Rename(string(imageFileName), path.Join(destination, id+".tar"))
	if err != nil {
		return diffID, err
	}

	// Dump the history next to it
	err = ioutil.WriteFile(path.Join(destination, id+".json"), []byte(meta), 0644)
	if err != nil {
		return diffID, err
	}

	progress.Update(progressOutput, image.String(), "Download complete")

	return diffID, nil
}

// tagOrDigest returns an image's digest if it's pulled by digest, or its tag
// otherwise.
func tagOrDigest(r reference.Named, tag string) string {
	if digested, ok := r.(reference.Canonical); ok {
		return digested.Digest().String()
	}

	return tag
}

// FetchImageManifest fetches the image manifest file
func FetchImageManifest(ctx context.Context, options Options, schemaVersion int, progressOutput progress.Output) (interface{}, string, error) {
	defer trace.End(trace.Begin(options.Reference.String()))

	if schemaVersion != 1 && schemaVersion != 2 {
		return nil, "", fmt.Errorf("Unknown schema version %d requested!", schemaVersion)
	}

	url, err := url.Parse(options.Registry)
	if err != nil {
		return nil, "", err
	}

	tagOrDigest := tagOrDigest(options.Reference, options.Tag)
	url.Path = path.Join(url.Path, options.Image, "manifests", tagOrDigest)
	log.Debugf("URL: %s", url)

	fetcher := urlfetcher.NewURLFetcher(urlfetcher.Options{
		Timeout:            options.Timeout,
		Username:           options.Username,
		Password:           options.Password,
		Token:              options.Token,
		InsecureSkipVerify: options.InsecureSkipVerify,
		RootCAs:            options.RegistryCAs,
	})

	reqHeaders := make(http.Header)
	if schemaVersion == 2 {
		reqHeaders.Add("Accept", schema2.MediaTypeManifest)
		reqHeaders.Add("Accept", schema1.MediaTypeManifest)
	}

	manifestFileName, err := fetcher.Fetch(ctx, url, &reqHeaders, true, progressOutput)
	if err != nil {
		return nil, "", err
	}

	// Cleanup function for the error case
	defer func() {
		if err != nil {
			os.Remove(manifestFileName)
		}
	}()

	switch schemaVersion {
	case 1: //schema 1, signed manifest
		return decodeManifestSchema1(manifestFileName, options, url.Hostname())
	case 2: //schema 2
		return decodeManifestSchema2(manifestFileName, options)
	}

	//We shouldn't really get here
	return nil, "", fmt.Errorf("Unknown schema version %d requested!", schemaVersion)
}

//// PutImageManifest simply pushes the manifest up to the registry.
//func PutImageManifest(ctx context.Context, manifest interface{}, ic Options, schemaVersion int, progressOutput progress.Output) error {
//	if schema2, ok := manifest.(*schema2.DeserializedManifest); !ok {
//	}
//
//	tr := &http.Transport{
//		Proxy: http.ProxyFromEnvironment,
//		TLSClientConfig: &tls.Config{
//			InsecureSkipVerify: options.InsecureSkipVerify,
//			RootCAs:            options.RootCAs,
//		},
//	}
//	client := &http.Client{Transport: tr}
//
//	// Create manifest push URL
//	url, err := url.Parse(options.Registry)
//	if err != nil {
//		return nil, "", err
//	}
//
//	tagOrDigest := tagOrDigest(options.Reference, options.Tag)
//	url.Path = path.Join(url.Path, options.Image, "manifests", tagOrDigest)
//	log.Debugf("URL: %s", url)
//
//	// Add content type headers
//	reqHeaders := make(http.Header)
//	var dataReader io.ByteReader
//
//	switch schemaVersion {
//	case 1: //schema 1, signed manifest
//		reqHeaders.Add("Content-Type", schema1.MediaTypeManifest)
//		dataReader := bytes.NewReader(option)
//	case 2: //schema 2
//		reqHeaders.Add("Content-Type", schema2.MediaTypeManifest)
//	}
//
//	req, err := http.NewRequest(http.MethodPut, url, data)
//	if err != nil {
//		return err
//	}
//
//	_, err = client.Do(req)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

// decodeManifestSchema1() reads a manifest schema 1 and creates an imageC
// defined Manifest structure and returns the digest of the manifest as a string.
// For historical reason, we did not use the Docker's defined schema1.Manifest
// instead of our own and probably should do so in the future.
func decodeManifestSchema1(filename string, options Options, registry string) (interface{}, string, error) {
	// Read the entire file into []byte for json.Unmarshal
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, "", err
	}

	manifest := &Manifest{}
	err = json.Unmarshal(content, manifest)
	if err != nil {
		return nil, "", err
	}

	digest, err := getManifestDigest(content, options.Reference)
	if err != nil {
		return nil, "", err
	}

	manifest.Digest = digest

	// Verify schema 1 manifest's fields per docker/docker/distribution/pull_v2.go
	numFSLayers := len(manifest.FSLayers)
	if numFSLayers == 0 {
		return nil, "", fmt.Errorf("no FSLayers in manifest")
	}
	if numFSLayers != len(manifest.History) {
		return nil, "", fmt.Errorf("length of history not equal to number of layers")
	}

	return manifest, digest, nil
}

// verifyManifestDigest checks the manifest digest against the received payload.
func verifyManifestDigest(digested reference.Canonical, bytes []byte) error {
	verifier, err := ddigest.NewDigestVerifier(digested.Digest())
	if err != nil {
		return err
	}
	if _, err = verifier.Write(bytes); err != nil {
		return err
	}
	if !verifier.Verified() {
		return fmt.Errorf("image manifest verification failed for digest %s", digested.Digest())
	}

	return nil
}

// decodeManifestSchema2() reads a manifest schema 2 and creates a Docker
// defined Manifest structure and returns the digest of the manifest as a string.
func decodeManifestSchema2(filename string, options Options) (interface{}, string, error) {
	// Read the entire file into []byte for json.Unmarshal
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, "", err
	}

	manifest := &schema2.DeserializedManifest{}

	err = json.Unmarshal(content, manifest)
	if err != nil {
		return nil, "", err
	}

	_, canonical, err := manifest.Payload()
	if err != nil {
		return nil, "", err
	}

	digest := ddigest.FromBytes(canonical)

	return manifest, string(digest), nil
}

func getManifestDigest(content []byte, ref reference.Named) (string, error) {
	jsonSig, err := libtrust.ParsePrettySignature(content, "signatures")
	if err != nil {
		return "", err
	}

	// Resolve the payload in the manifest.
	bytes, err := jsonSig.Payload()
	if err != nil {
		return "", err
	}

	log.Debugf("Canonical Bytes: %d", len(bytes))

	// Verify the manifest digest if the image is pulled by digest. If the image
	// is not pulled by digest, we proceed without this check because we don't
	// have a digest to verify the received content with.
	// https://docs.docker.com/registry/spec/api/#content-digests
	if digested, ok := ref.(reference.Canonical); ok {
		if err := verifyManifestDigest(digested, bytes); err != nil {
			return "", err
		}
	}

	digest := ddigest.FromBytes(bytes)
	// Correct Manifest Digest
	log.Debugf("Manifest Digest: %v", digest)
	return string(digest), nil
}

// PushImageBlob fetches the image blob
// harcode layer diffID(digest) and layer tar using mock data
//func PushImageBlob(ctx context.Context, options Options, image *ImageWithMeta, progressOutput progress.Output) error {
func PushImageBlob(ctx context.Context, options Options, progressOutput progress.Output) (err error) {
	defer trace.End(trace.Begin(options.Image))

	// mimicking vanilla docker's push_v2.go:Upload()
	// the workflow: (https://docs.docker.com/registry/spec/api/#pushing-an-image)
	// 0) start an upload: POST /v2/<name>/blobs/uploads/; this will return the upload url in "location" of the response header
	// 1) check if layer already exists: HEAD /v2/<name>/blobs/<digest>; if yes, complete upload by jumping to 3)
	// 2) upload the layer tar (monolithic upload): PUT /v2/<name>/blobs/uploads/<uuid>?digest=<digest>; here the upload url is obtained in 0); layer binary will be in the request body
	// 3) completed upload: PUT /v2/<name>/blob/uploads/<uuid>?digest=<digest> with 0-length body
	// Cheng: I think the order of 0) and 1) could be changed so that we don't need 3) after 1)

	// TODO: add retry logic; or maybe put the retry logic in upload manager

	log.Debugf("The registry in use is: %s", options.Registry)
	registryUrl, err := url.Parse(options.Registry)
	if err != nil {
		return err
	}

	pusher := urlfetcher.NewURLPusher(urlfetcher.Options{
		Timeout:            options.Timeout,
		Username:           options.Username,
		Password:           options.Password,
		Token:              options.Token,
		InsecureSkipVerify: options.InsecureSkipVerify,
		RootCAs:            options.RegistryCAs,
	})
	//
	////------------------step 1-----------------
	//// the layer tar might be passed into this function in the stream format instead of a stored variable
	//// here I just use mock data
	bigBuff := make([]byte, 1024000)
	err = ioutil.WriteFile("layer.tar", bigBuff, 0666)
	if err != nil {
		return err
	}
	defer os.Remove("layer.tar")

	layer, err := ioutil.ReadFile("layer.tar")
	if err != nil {
		return err
	}

	//var buf bytes.Buffer
	//zw := gzip.NewWriter(&buf)
	//
	//nn, err := zw.Write(layer)
	//if err != nil {
	//	return fmt.Errorf("failed when compressing layer: %s", err)
	//}
	//log.Debugf("The layer is compressed into %d bytes", nn)
	//
	//zr, err := gzip.NewReader(&buf)
	//if err != nil {
	//	return fmt.Errorf("failed when compressing layer: %s", err)
	//}

	////--------from docker-----------
	//var reader io.ReadCloser
	//contentReader := ioutil.NopCloser(bytes.NewBuffer(layer))
	//size := int64(1024000)
	//reader = progress.NewProgressReader(ioutils.NewCancelReadCloser(ctx, contentReader), progressOutput, size, "mock layer", "Pushing")
	//
	//compressedReader, compressionDone := compress(reader)
	//defer func(closer io.Closer) {
	//	closer.Close()
	//	<-compressionDone
	//}(reader)
	//reader = compressedReader
	//
	//digester := digest.Canonical.New()
	//tee := io.TeeReader(reader, digester.Hash())
	//pushDigest := digester.Digest().String()
	//log.Debugf("The push digest is: %s", pushDigest)
	//-----------------------------

	diffIDSum := sha256.New()
	diffIDSum.Write([]byte(layer))
	//diffIDSum.Write(buf.Bytes())
	pushDigest := fmt.Sprintf("sha256:%x", diffIDSum.Sum(nil))
	log.Infof("The calculated tar digest for the mock data is: %s", pushDigest)

	exist, err := pusher.CheckLayerExistence(ctx, options.Image, pushDigest, registryUrl)
	if err != nil {
		return fmt.Errorf("failed to check layer existence: %s", err)
	}
	if exist {
		// layer already exists; so no need to upload
		layerID := "layerID"
		progress.Update(progressOutput, layerID, "Layer already exists")
		return nil
	}

	/////////////////////////////////////////////
	//// obtain a list of repositories for cross repo blob mount
	//res, err := ObtainRepoList(options, progressOutput)
	//if err != nil {
	//	log.Errorf("Failed to fetch repo list: %s", err)
	//} else {
	//	log.Infof("The repo list is: %s", res)
	//}
	////////////////////////////////////////////
	//repoList := []string{"atest/busybox", "cheng-test/busybox", "test/busybox"} // kang.eng.vmware.com
	repoList := []string{"patiner/aaa", "patiner/ubuntu", "patiner/busybox", "patiner/test"}  //dockerhub
	mounted, err := CrossRepoBlobMount(ctx, pushDigest, options, repoList, progressOutput)
	if err != nil {
		return fmt.Errorf("failed during CrossRepoBlobMount: %s", err)
	}
	if mounted {
		layerID := "layerID"
		progress.Update(progressOutput, layerID, "Layer already mounted")
		return nil
	}

	//--------------------step 0---------------
	// obtain upload url to start upload process
	// which would require obtaining a list of the repositories that the current user has access to.
	// See https://docs.docker.com/registry/spec/api/#pushing-an-image
	// vanilla docker does this as well
	// TODO: instead of directly obtaining the upload url, we could try "Cross Repository Blob Mount"

	uploadURL, err := pusher.ObtainUploadUrl(ctx, registryUrl, options.Image)
	if err != nil {
		return err
	}
	log.Infof("The upload url is: %s", uploadURL)

	defer func() {
		if err != nil {
			if err2 := pusher.CancelUpload(ctx, uploadURL); err2 != nil {
				log.Errorf("Failed during CancelUpload: %s", err2)
			}
		} else {
			//----------------no need for step 3 since we use monolithic upload---------------
		}
	}()

	//-----------------step 2------------------
	if err = pusher.UploadLayer(ctx, pushDigest, uploadURL, "", bytes.NewBuffer(layer)); err != nil {
		//if err = pusher.UploadLayer(ctx, pushDigest, uploadURL, "", tee); err != nil {
		//if err = pusher.UploadLayer(ctx, pushDigest, uploadURL, "", zr); err != nil {
		return err
	}

	return nil
}

func CrossRepoBlobMount(ctx context.Context, digest string, options Options, repoList []string, po progress.Output) (bool, error) {
	defer trace.End(trace.Begin(options.Image))

	log.Infof("The list of repositories is: %+v", repoList)

	var (
		mounted  bool
		authURL  *url.URL
		newToken *urlfetcher.Token
	)

	registry, err := url.Parse(options.Registry)
	if err != nil {
		return false, err
	}

	for _, repo := range repoList {

		// first obtain the auth url and token
		composedUrl, _ := url.Parse(options.Registry)
		composedUrl.Path = path.Join(composedUrl.Path, options.Image, "blobs/uploads")
		composedUrl.Path += "/"

		q := composedUrl.Query()
		q.Add("mount", digest)
		q.Add("from", repo)
		composedUrl.RawQuery = q.Encode()

		log.Infof("The url for MountBlobToRepo is: %s\n ", composedUrl)

		// POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repository name>
		// Content-Length: 0
		reqHdrs := &http.Header{
			"Content-Length": {"0"},
		}

		pusher := urlfetcher.NewURLPusher(urlfetcher.Options{
			Timeout:            options.Timeout,
			Username:           options.Username,
			Password:           options.Password,
			InsecureSkipVerify: options.InsecureSkipVerify,
			RootCAs:            options.RegistryCAs,
		})

		// We expect docker registry to return a 401 to us - with a WWW-Authenticate header
		// We parse that header and learn the OAuth endpoint to fetch OAuth token.
		hdr, err := pusher.Push(ctx, composedUrl, bytes.NewReader([]byte("")), reqHdrs, "POST")

		if err != nil {
			return false, err
		}

		if pusher.IsStatusUnauthorized() {
			authURL, err = pusher.ExtractOAuthURL(hdr.Get("www-authenticate"), composedUrl)
			if err != nil {
				return false, err
			}
		}

		log.Infof("The url for authenticating CrossRepoBlobMount is: %+v", authURL)

		// Get the OAuth token - if only we have a URL
		if authURL != nil {
			newToken, err = FetchToken(ctx, options, authURL, po)
			if err != nil {
				log.Errorf("Failed to fetch OAuth token: %s", err)
				return false, err
			}
		}

		newPusher := urlfetcher.NewURLPusher(urlfetcher.Options{
			Timeout:            options.Timeout,
			Username:           options.Username,
			Password:           options.Password,
			Token:              newToken,
			InsecureSkipVerify: options.InsecureSkipVerify,
			RootCAs:            options.RegistryCAs,
		})

		// if mount fails, the registry will fall back to the standard upload behavior
		// and return a 202 Accepted with the upload URL in the Location header
		mounted, _, err = newPusher.MountBlobToRepo(ctx, registry, digest, options.Image, repo)
		if err != nil {
			log.Errorf("Mount layer to repo %s failed: %s", repo, err)
			//return false, err
		}
		if mounted {
			break
		}
	}

	if mounted {
		return true, nil
	}

	log.Debugf("Layer is not mounted")
	return false, nil
}

// LearnAuthURLForPush returns the URL of the OAuth endpoint
func LearnAuthURLForPush(options Options) (*url.URL, error) {
	defer trace.End(trace.Begin(options.Reference.String()))

	url, err := url.Parse(options.Registry)
	if err != nil {
		return nil, err
	}

	url.Path = path.Join(url.Path, options.Image, "blobs", "uploads")
	url.Path += "/"
	log.Debugf("LearnAuthURLForPush URL: %s", url)

	pusher := urlfetcher.NewURLPusher(urlfetcher.Options{
		Timeout:            options.Timeout,
		Username:           options.Username,
		Password:           options.Password,
		InsecureSkipVerify: options.InsecureSkipVerify,
		RootCAs:            options.RegistryCAs,
	})

	// We expect docker registry to return a 401 to us - with a WWW-Authenticate header
	// We parse that header and learn the OAuth endpoint to fetch OAuth token.
	hdr, err := pusher.Push(ctx, url, bytes.NewReader([]byte("")), nil, "POST")

	if err != nil {
		return nil, err
	}

	if err == nil && pusher.IsStatusUnauthorized() {
		return pusher.ExtractOAuthURL(hdr.Get("www-authenticate"), url)
	}

	return nil, fmt.Errorf("Unexpected http code: %d, URL: %s", pusher.Status(), url)
}

// ObtainRepoList
func ObtainRepoList(options Options, progressOutput progress.Output) (string, error) {
	defer trace.End(trace.Begin(options.Reference.String()))

	_, token, err := obtainRepoList(options, nil, progressOutput)
	if err != nil {
		return "", err
	}

	repoList, _, err := obtainRepoList(options, token, progressOutput)
	if err != nil {
		return "", err
	}

	return repoList, nil
}

func obtainRepoList(options Options, token *urlfetcher.Token, progressOutput progress.Output) (string, *urlfetcher.Token, error) {
	url, err := url.Parse(options.Registry)
	if err != nil {
		return "", nil, err
	}

	url.Path = path.Join(url.Path, "_catalog")
	log.Debugf("obtainRepolist URL: %s", url)

	fetcher := urlfetcher.NewURLFetcher(urlfetcher.Options{
		Timeout:            options.Timeout,
		Username:           options.Username,
		Password:           options.Password,
		InsecureSkipVerify: options.InsecureSkipVerify,
		RootCAs:            options.RegistryCAs,
		Token:              token,
	})

	// We expect docker registry to return a 401 to us if token is nil - with a WWW-Authenticate header
	// We parse that header and learn the OAuth endpoint to fetch OAuth token.
	rdr, hdr, err := fetcher.FetchWithHeaderAndBody(ctx, url, nil)
	if err != nil {
		return "", nil, err
	}
	defer rdr.Close()

	if err == nil && fetcher.IsStatusUnauthorized() {
		oauthUrl, err := fetcher.ExtractOAuthURL(hdr.Get("www-authenticate"), url)
		if err != nil {
			return "", nil, fmt.Errorf("failed to extact oauth url: %s", err)
		}

		token, err = FetchToken(ctx, options, oauthUrl, progressOutput)
		if err != nil {
			return "", nil, fmt.Errorf("failed to fetch OAuth token: %s", err)
		}
		return "", token, nil
	}

	if fetcher.IsStatusOK() {
		out := bytes.NewBuffer(nil)

		// Stream into it
		_, err = io.Copy(out, rdr)
		if err != nil {
			// cleanup
			return "", nil, err
		}
		return string(out.Bytes()), nil, nil
	}

	return "", nil, fmt.Errorf("Unexpected http code: %d, URL: %s", fetcher.Status(), url)
}

func compress(in io.Reader) (io.ReadCloser, chan struct{}) {
	compressionDone := make(chan struct{})

	pipeReader, pipeWriter := io.Pipe()
	// Use a bufio.Writer to avoid excessive chunking in HTTP request.
	bufWriter := bufio.NewWriterSize(pipeWriter, compressionBufSize)
	compressor := gzip.NewWriter(bufWriter)

	go func() {
		_, err := io.Copy(compressor, in)
		if err == nil {
			err = compressor.Close()
		}
		if err == nil {
			err = bufWriter.Flush()
		}
		if err != nil {
			pipeWriter.CloseWithError(err)
		} else {
			pipeWriter.Close()
		}
		close(compressionDone)
	}()

	return pipeReader, compressionDone
}
