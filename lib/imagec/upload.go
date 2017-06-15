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

	"github.com/moby/moby/pkg/progress"
	"github.com/vmware/vic/pkg/trace"
)

type uploadTransfer struct {
}

// LayerUploader uploads layers
type LayerUploader struct {
	tm TransferManager
}

const (
	maxUploadAttempts    = 5
	maxConcurrentUploads = 3
)

// NewLayerUploader creates a new LayerUploader
func NewLayerUploader() *LayerUploader {
	return &LayerUploader{
		tm: NewTransferManager(maxConcurrentUploads),
	}
}

// UploadLayers starts the upload of all layers contained in the ImageC argument
func (lum *LayerUploader) UploadLayers(ctx context.Context, ic *ImageC) error {
	defer trace.End(trace.Begin(""))

	var (
		uploads      []*uploadTransfer
		currTransfer = make(map[string]*uploadTransfer)
	)

	for _, layer := range ic.ImageLayers {
		progress.Update(progressOutput, descriptor.ID(), "Preparing")

		if _, present := currTransfer[layer.ID]; present {
			continue
		}

		layerConfig, err := LayerCache().Get(layer.ID)
		if err != nil {
			return err
		}

		xferFunc := lum.makeUploadFunc(layer)
		upload, watcher := lum.tm.Transfer(descriptor.Key(), xferFunc, progressOutput)
		defer upload.Release(watcher)
		uploads = append(uploads, upload.(*uploadTransfer))
		dedupDescriptors[key] = upload.(*uploadTransfer)

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
	return nil
}

func (lum *LayerUploader) makeUploadFunc(descriptor UploadDescriptor) DoFunc {
	return func(progressChan chan<- progress.Progress, start <-chan struct{}, inactive chan<- struct{}) Transfer {
		u := &uploadTransfer{
			Transfer: NewTransfer(),
		}

		go func() {
			defer func() {
				close(progressChan)
			}()

			progressOutput := progress.ChanOutput(progressChan)

			select {
			case <-start:
			default:
				progress.Update(progressOutput, descriptor.ID(), "Waiting")
				<-start
			}

			retries := 0
			for {
				remoteDescriptor, err := descriptor.Upload(u.Transfer.Context(), progressOutput)
				if err == nil {
					u.remoteDescriptor = remoteDescriptor
					break
				}

				// If an error was returned because the context
				// was cancelled, we shouldn't retry.
				select {
				case <-u.Transfer.Context().Done():
					u.err = err
					return
				default:
				}

				retries++
				if _, isDNR := err.(DoNotRetry); isDNR || retries == maxUploadAttempts {
					logrus.Errorf("Upload failed: %v", err)
					u.err = err
					return
				}

				logrus.Errorf("Upload failed, retrying: %v", err)
				delay := retries * 5
				ticker := time.NewTicker(time.Second)

			selectLoop:
				for {
					progress.Updatef(progressOutput, descriptor.ID(), "Retrying in %d second%s", delay, (map[bool]string{true: "s"})[delay != 1])
					select {
					case <-ticker.C:
						delay--
						if delay == 0 {
							ticker.Stop()
							break selectLoop
						}
					case <-u.Transfer.Context().Done():
						ticker.Stop()
						u.err = errors.New("upload cancelled during retry delay")
						return
					}
				}
			}
		}()

		return u
	}
}
