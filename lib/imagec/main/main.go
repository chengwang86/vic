package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
)


type maxBytesReader struct {
	w   http.ResponseWriter
	r   io.ReadCloser // underlying reader
	n   int64         // max bytes remaining
	err error         // sticky error
}

func main() {
	fmt.Println("Hello, playground")

	// the desired URL for upload layer should be "PUT /v2/<name>/blob/uploads/<uuid>?digest=<digest>"
	// here "/v2/<name>/blob/uploads/<uuid" is obtained from the registry as "uploadUrl"
	uploadUrl := "https://kang.eng.vmware.com/v2/cheng-test/busybox/blobs/uploads/ebae033d-a1b7-4db1-8af3-f13fc0c87a4e?_state=xxxx"
	digest := "sha256:abcd"

	composedUrl, _ := url.Parse(uploadUrl)
	//composedUrl.Path += "?digest=" + digest

	fmt.Printf("The rawquery is: %s\n", composedUrl.RawQuery)
	fmt.Printf("The path is: %s\n", composedUrl.Path)

	q := composedUrl.Query()
	fmt.Printf("-----q %+v\n", q)
	q.Add("digest", digest)
	fmt.Printf("-----q %+v\n", q)
	composedUrl.RawQuery = q.Encode()

	fmt.Printf("The rawquery is: %s\n", composedUrl.RawQuery)
	fmt.Printf("The path is: %s\n", composedUrl.Path)

	fmt.Printf("The encoded url is: %s\n", composedUrl)

	r, _ := http.NewRequest("PUT", composedUrl.String(), bytes.NewReader([]byte("abcd")))

	fmt.Printf("The raw query from req is: %s\n", r.URL.RawQuery)
	fmt.Printf("The url from req is: %+v\n", r.URL)

	fmt.Printf("r.Form: %+v\n", r.Form)
	//err := r.ParseForm()

	//if err != nil {
	//	fmt.Println(err)
	//}
	var newValues url.Values
	var e, err error

	if r.URL != nil {
		newValues = make(url.Values)
		err := parseQuery(newValues, r.URL.RawQuery)
		if err == nil {
			err = e
		}
	}
	fmt.Printf("---------newValues: %+v\n", newValues)
	if newValues == nil {
		newValues = make(url.Values)
	}
	if r.Form == nil {
		r.Form = newValues
	} else {
		copyValues(r.Form, newValues)
	}
	fmt.Printf("r.Form: %+v\n", r.Form)
	state := r.Form.Get("_state")

	//state := r.FormValue("_state")
	fmt.Println("The form value of state is: ", state)

	_, err = base64.URLEncoding.DecodeString(state)
	if err != nil {
		fmt.Println("Failed to decode: %s", err)
	}

	ParseForm(r)

	fmt.Printf("----------now the form data is: %+v\n", r.Form)
	d := r.FormValue("digest")
	fmt.Println("The digest is: ", d)

	//str := "_state=xxxx&digest=sha256%3Aabcd"
	//m := make(url.Values)
	//parseQuery(m, str)

}

func ParseForm(r *http.Request) error {
	var err error
	fmt.Printf("The post form is: %+v\n", r.PostForm)
	fmt.Printf("The form is: %+v\n", r.Form)
	if r.PostForm == nil {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			r.PostForm, err = parsePostForm(r)
		}
		if r.PostForm == nil {
			r.PostForm = make(url.Values)
		}
	}
	if r.Form == nil {
		if len(r.PostForm) > 0 {
			r.Form = make(url.Values)
			copyValues(r.Form, r.PostForm)
		}
		var newValues url.Values
		if r.URL != nil {
			var e error
			newValues, e = url.ParseQuery(r.URL.RawQuery)
			if err == nil {
				err = e
			}
		}
		fmt.Printf("--------The new values: %+v\n", newValues)
		if newValues == nil {
			newValues = make(url.Values)
		}
		if r.Form == nil {
			r.Form = newValues
		} else {
			copyValues(r.Form, newValues)
		}
	}
	return err
}

func copyValues(dst, src url.Values) {
	for k, vs := range src {
		for _, value := range vs {
			dst.Add(k, value)
		}
	}
}

func parsePostForm(r *http.Request) (vs url.Values, err error) {
	if r.Body == nil {
		err = errors.New("missing form body")
		return
	}
	ct := r.Header.Get("Content-Type")
	// RFC 2616, section 7.2.1 - empty type
	//   SHOULD be treated as application/octet-stream
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, _, err = mime.ParseMediaType(ct)
	switch {
	case ct == "application/x-www-form-urlencoded":
		var reader io.Reader = r.Body
		maxFormSize := int64(1<<63 - 1)
		if _, ok := r.Body.(*maxBytesReader); !ok {
			maxFormSize = int64(10 << 20) // 10 MB is a lot of text.
			reader = io.LimitReader(r.Body, maxFormSize+1)
		}
		b, e := ioutil.ReadAll(reader)
		if e != nil {
			if err == nil {
				err = e
			}
			break
		}
		if int64(len(b)) > maxFormSize {
			err = errors.New("http: POST too large")
			return
		}
		vs, e = url.ParseQuery(string(b))
		if err == nil {
			err = e
		}
	case ct == "multipart/form-data":
		// handled by ParseMultipartForm (which is calling us, or should be)
		// TODO(bradfitz): there are too many possible
		// orders to call too many functions here.
		// Clean this up and write more tests.
		// request_test.go contains the start of this,
		// in TestParseMultipartFormOrder and others.
	}
	return
}

func parseQuery(m url.Values, query string) (err error) {
	for query != "" {
		fmt.Printf("----now the query is: %s\n", query)
		key := query
		if i := strings.IndexAny(key, "&;"); i >= 0 {
			key, query = key[:i], key[i+1:]
			fmt.Printf("key: %s, query: %s\n", key, query)
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.Index(key, "="); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key, err1 := url.QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		value, err1 = url.QueryUnescape(value)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		fmt.Printf("finally key: %s, value: %s\n", key, value)
		m[key] = append(m[key], value)
	}
	fmt.Printf("m: %+v\n", m)
	return err
}

func (l *maxBytesReader) Read(p []byte) (n int, err error) {
	if l.err != nil {
		return 0, l.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// If they asked for a 32KB byte read but only 5 bytes are
	// remaining, no need to read 32KB. 6 bytes will answer the
	// question of the whether we hit the limit or go past it.
	if int64(len(p)) > l.n+1 {
		p = p[:l.n+1]
	}
	n, err = l.r.Read(p)

	if int64(n) <= l.n {
		l.n -= int64(n)
		l.err = err
		return n, err
	}

	n = int(l.n)
	l.n = 0

	// The server code and client code both use
	// maxBytesReader. This "requestTooLarge" check is
	// only used by the server code. To prevent binaries
	// which only using the HTTP Client code (such as
	// cmd/go) from also linking in the HTTP server, don't
	// use a static type assertion to the server
	// "*response" type. Check this interface instead:
	type requestTooLarger interface {
		requestTooLarge()
	}
	if res, ok := l.w.(requestTooLarger); ok {
		res.requestTooLarge()
	}
	l.err = errors.New("http: request body too large")
	return n, l.err
}

func (l *maxBytesReader) Close() error {
	return l.r.Close()
}