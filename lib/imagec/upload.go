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
// See the License for the specific language governing permissi[ons and
// limitations under the License.

package imagec

import (
	"context"

	"github.com/docker/docker/distribution/xfer"
	"github.com/docker/docker/pkg/progress"
	"github.com/docker/docker/pkg/streamformatter"
	"github.com/vmware/vic/pkg/trace"
)

// LayerUploader uploads layers
type LayerUploader struct {
	tm xfer.TransferManager
}

type uploadTransfer struct {
	xfer.Transfer

	err error
}

const (
	maxUploadAttempts    = 5
	maxConcurrentUploads = 3
)

// NewLayerUploader creates a new LayerUploader
func NewLayerUploader() *LayerUploader {
	return &LayerUploader{
		tm: xfer.NewTransferManager(maxConcurrentUploads),
	}
}

// UploadLayers starts the upload of all layers contained in the ImageC argument
func (lum *LayerUploader) UploadLayers(ctx context.Context, ic *ImageC) error {
	defer trace.End(trace.Begin(""))

	var (
		uploads        []*uploadTransfer
		currTransfer   = make(map[string]*uploadTransfer)
		sf             = streamformatter.NewJSONStreamFormatter()
		progressOutput = &serialProgressOutput{
			c:   make(chan prog, 100),
			out: sf.NewProgressOutput(ic.Outstream, false),
		}
	)

	for _, layer := range ic.ImageLayers {
		progress.Update(progressOutput, layer.String(), "Preparing")

		// Check if already uploading
		if _, present := currTransfer[layer.ID]; present {
			continue
		}

		xferFunc := lum.makeUploadFunc(layer, ic)
		upload, watcher := lum.tm.Transfer(layer.ID, xferFunc, progressOutput)
		defer upload.Release(watcher)
		uploads = append(uploads, upload.(*uploadTransfer))
		currTransfer[layer.ID] = upload.(*uploadTransfer)
	}

	for _, upload := range uploads {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-upload.Transfer.Done():
			if upload.err != nil {
				return upload.err
			}
		}
	}

	return nil
}

func (lum *LayerUploader) makeUploadFunc(layer *ImageWithMeta, ic *ImageC) xfer.DoFunc {
	return func(progressChan chan<- progress.Progress, start <-chan struct{}, inactive chan<- struct{}) xfer.Transfer {
		u := &uploadTransfer{
			Transfer: xfer.NewTransfer(),
		}

		reader, err := ic.Pusher.GetReaderForLayer(layer.ID)
		if err != nil {
			u.err = err
			return u
		}

		pusher := ic.Pusher
		as := pusher.streamMap[layer.ID]

		go func() {
			select {
			case <-u.Transfer.Done():
				reader.Close()
			}
		}()

		go func() {
			defer func() {
				close(progressChan)
			}()

			progressOutput := progress.ChanOutput(progressChan)

			select {
			case <-start:
			default:
				progress.Update(progressOutput, layer.String(), "Waiting")
				<-start
			}

			// PutImageBlob will handle retries and backoff
			err := PushImageBlob(u.Transfer.Context(), ic.Options, as, reader, progressOutput)
			if err != nil {
				// log.Errorf("Error pushing image blob for %s/%s: %s", ic.Image, layer.ID, err)
				return
			}
		}()

		return u
	}
}
