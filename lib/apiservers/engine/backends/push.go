package backends

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/vmware/vic/lib/apiservers/engine/backends/cache"
	"github.com/vmware/vic/lib/imagec"
	"github.com/vmware/vic/pkg/trace"

	log "github.com/Sirupsen/logrus"

	"github.com/docker/distribution/digest"
	"github.com/docker/docker/api/types"
	eventtypes "github.com/docker/docker/api/types/events"
	"github.com/docker/docker/pkg/streamformatter"
	"github.com/docker/docker/reference"
)

// PushImage initiates a push operation on the repository named localName.
func (i *Image) PushImage(ctx context.Context, image, tag string, metaHeaders map[string][]string, authConfig *types.AuthConfig, outStream io.Writer) error {
	// return fmt.Errorf("%s does not yet implement image.PushImage", ProductName())
	defer trace.End(trace.Begin(fmt.Sprintf("%s:%s", image, tag)))

	img, err := cache.ImageCache().Get(image)
	if err != nil {
		return ImageNotFoundError(image, tag)
	}

	log.Debugf("PushImage: image = %s, tag = %s, metaheaders = %+v\n, authConfig = %+v\n", image, tag, metaHeaders, authConfig)

	//***** Code from Docker 1.13 PullImage to convert image and tag to a ref
	image = strings.TrimSuffix(image, ":")

	ref, err := reference.ParseNamed(image)
	if err != nil {
		return err
	}

	if tag != "" {
		// The "tag" could actually be a digest.
		var dgst digest.Digest
		dgst, err = digest.ParseDigest(tag)
		if err == nil {
			ref, err = reference.WithDigest(reference.TrimNamed(ref), dgst)
		} else {
			ref, err = reference.WithTag(ref, tag)
		}
		if err != nil {
			return err
		}
	}
	//*****

	// create url from hostname
	hostnameURL, err := url.Parse(ref.Hostname())
	if err != nil || hostnameURL.Hostname() == "" {
		hostnameURL, err = url.Parse("//" + ref.Hostname())
		if err != nil {
			log.Infof("Error parsing hostname %s during registry access: %s", ref.Hostname(), err.Error())
		}
	}

	options := imagec.Options{
		Destination: os.TempDir(),
		Reference:   ref,
		Timeout:     imagec.DefaultHTTPTimeout,
		Outstream:   outStream,
	}

	// Check if url is contained within set of whitelisted or insecure registries
	whitelistOk, _, insecureOk := vchConfig.RegistryCheck(ctx, hostnameURL)
	if !whitelistOk {
		err = fmt.Errorf("Access denied to unauthorized registry (%s) while VCH is in whitelist mode", hostnameURL.Host)
		log.Errorf(err.Error())
		sf := streamformatter.NewJSONStreamFormatter()
		outStream.Write(sf.FormatError(err))
		return nil
	}
	options.InsecureAllowHTTP = insecureOk

	options.RegistryCAs = RegistryCertPool

	if authConfig != nil {
		if len(authConfig.Username) > 0 {
			options.Username = authConfig.Username
		}
		if len(authConfig.Password) > 0 {
			options.Password = authConfig.Password
		}
	}

	portLayerServer := PortLayerServer()

	if portLayerServer != "" {
		options.Host = portLayerServer
	}

	log.Infof("PushImage: reference: %s, %s, portlayer: %#v",
		options.Reference,
		options.Host,
		portLayerServer)

	log.Infof("-------------The imagecOption:-----------\n %+v", options)

	ic := imagec.NewImageC(options, streamformatter.NewJSONStreamFormatter())
	err = ic.PushImage()
	if err != nil {
		return err
	}

	//TODO:  Need repo name as second parameter.  Leave blank for now
	actor := CreateImageEventActorWithAttributes(image, "", map[string]string{})
	EventService().Log("pull", eventtypes.ImageEventType, actor)
	return nil
}

func SimpleArchiveReader(ctx context.Context, layerID string) (io.ReadCloser, error) {

}
