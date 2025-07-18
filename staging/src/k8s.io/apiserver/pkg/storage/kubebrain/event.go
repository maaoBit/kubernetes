/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubebrain

import (
	rpc "github.com/kubewharf/kubebrain-client/api/v2rpc"
)

// kubebrain的event只包含curKeyValues
type event struct {
	key              string
	value            []byte
	rev              int64
	isDeleted        bool
	isCreated        bool
	isProgressNotify bool
}

// parseKV converts a KeyValue retrieved from an initial sync() listing to a synthetic isCreated event.
func parseKV(kv *rpc.KeyValue) *event {
	return &event{
		key:       string(kv.Key),
		value:     kv.Value,
		rev:       int64(kv.Revision),
		isDeleted: false,
		isCreated: true,
	}
}

func parseEvent(e *rpc.Event) (*event, error) {
	ret := &event{
		key:       string(e.Kv.Key),
		value:     e.Kv.Value,
		rev:       int64(e.Kv.Revision),
		isDeleted: e.Type == rpc.Event_DELETE,
		isCreated: e.Type == rpc.Event_CREATE,
	}
	return ret, nil
}

func progressNotifyEvent(rev int64) *event {
	return &event{
		rev:              rev,
		isProgressNotify: true,
	}
}
