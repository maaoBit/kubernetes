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
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/kubewharf/kubebrain-client/client"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/value"
	utilflowcontrol "k8s.io/apiserver/pkg/util/flowcontrol"

	"k8s.io/klog/v2"
)

const (
	// We have set a buffer in order to reduce times of context switches.
	incomingBufSize = 100
	outgoingBufSize = 100
)

// fatalOnDecodeError is used during testing to panic the server if watcher encounters a decoding error
var fatalOnDecodeError = false

// errTestingDecode is the only error that testingDeferOnDecodeError catches during a panic
var errTestingDecode = errors.New("sentinel error only used during testing to indicate watch decoding error")

// testingDeferOnDecodeError is used during testing to recover from a panic caused by errTestingDecode, all other values continue to panic
func testingDeferOnDecodeError() {
	if r := recover(); r != nil && r != errTestingDecode {
		panic(r)
	}
}

func init() {
	// check to see if we are running in a test environment
	TestOnlySetFatalOnDecodeError(true)
	fatalOnDecodeError, _ = strconv.ParseBool(os.Getenv("KUBE_PANIC_WATCH_DECODE_ERROR"))
}

// TestOnlySetFatalOnDecodeError should only be used for cases where decode errors are expected and need to be tested. e.g. conversion webhooks.
func TestOnlySetFatalOnDecodeError(b bool) {
	fatalOnDecodeError = b
}

type watcher struct {
	client      client.Client
	codec       runtime.Codec
	newFunc     func() runtime.Object
	objectType  string
	versioner   storage.Versioner
	transformer value.Transformer
}

// watchChan implements watch.Interface.
type watchChan struct {
	watcher        *watcher
	key            string
	initialRev     int64
	recursive      bool
	progressNotify bool
	// 目前wc.internalPred的赋值始终是"k8s.io/apiserver/pkg/storage"的Everything
	// 见staging/src/k8s.io/apiserver/pkg/storage/etcd3/watcher.go 149L
	// 以及staging/src/k8s.io/apiserver/pkg/storage/cacher/cacher.go 1118L
	// kubebrain的Event只有curKeyValues
	// etcd中如果internalPred不是Everything，则需要处理preKeyValue
	// 在kubebrain storage暂时忽略
	internalPred      storage.SelectionPredicate
	ctx               context.Context
	cancel            context.CancelFunc
	incomingEventChan chan *event
	resultChan        chan watch.Event
	errChan           chan error
}

func newWatcher(client client.Client, codec runtime.Codec, newFunc func() runtime.Object, versioner storage.Versioner, transformer value.Transformer) *watcher {
	res := &watcher{
		client:      client,
		codec:       codec,
		newFunc:     newFunc,
		versioner:   versioner,
		transformer: transformer,
	}
	if newFunc == nil {
		res.objectType = "<unknown>"
	} else {
		res.objectType = reflect.TypeOf(newFunc()).String()
	}
	return res
}

// Watch watches on a key and returns a watch.Interface that transfers relevant notifications.
// If rev is zero, it will return the existing object(s) and then start watching from
// the maximum revision+1 from returned objects.
// If rev is non-zero, it will watch events happened after given revision.
// If recursive is false, it watches on given key.
// If recursive is true, it watches any children and directories under the key, excluding the root key itself.
// pred must be non-nil. Only if pred matches the change, it will be returned.
func (w *watcher) Watch(ctx context.Context, key string, rev int64, recursive, progressNotify bool, pred storage.SelectionPredicate) (watch.Interface, error) {
	if recursive && !strings.HasSuffix(key, "/") {
		key += "/"
	}
	wc := w.createWatchChan(ctx, key, rev, recursive, progressNotify, pred)
	go wc.run()

	// For etcd watch we don't have an easy way to answer whether the watch
	// has already caught up. So in the initial version (given that watchcache
	// is by default enabled for all resources but Events), we just deliver
	// the initialization signal immediately. Improving this will be explored
	// in the future.
	utilflowcontrol.WatchInitialized(ctx)

	return wc, nil
}

func (w *watcher) createWatchChan(ctx context.Context, key string, rev int64, recursive, progressNotify bool, pred storage.SelectionPredicate) *watchChan {
	wc := &watchChan{
		watcher:           w,
		key:               key,
		initialRev:        rev,
		recursive:         recursive,
		progressNotify:    progressNotify,
		internalPred:      pred,
		incomingEventChan: make(chan *event, incomingBufSize),
		resultChan:        make(chan watch.Event, outgoingBufSize),
		errChan:           make(chan error, 1),
	}
	if pred.Empty() {
		// The filter doesn't filter out any object.
		wc.internalPred = storage.Everything
	}

	// todo: kubebrain不支持类似lientv3.WithRequireLeader(ctx)
	wc.ctx, wc.cancel = context.WithCancel(ctx)
	return wc
}

func (wc *watchChan) run() {
	watchClosedCh := make(chan struct{})
	go wc.startWatching(watchClosedCh)

	var resultChanWG sync.WaitGroup
	resultChanWG.Add(1)
	go wc.processEvent(&resultChanWG)

	select {
	case err := <-wc.errChan:
		if err == context.Canceled {
			break
		}
		errResult := transformErrorToEvent(err)
		if errResult != nil {
			// error result is guaranteed to be received by user before closing ResultChan.
			select {
			case wc.resultChan <- *errResult:
			case <-wc.ctx.Done(): // user has given up all results
			}
		}
	case <-watchClosedCh:
	case <-wc.ctx.Done(): // user cancel
	}

	// We use wc.ctx to reap all goroutines. Under whatever condition, we should stop them all.
	// It's fine to double cancel.
	wc.cancel()

	// we need to wait until resultChan wouldn't be used anymore
	resultChanWG.Wait()
	close(wc.resultChan)
}

func (wc *watchChan) Stop() {
	wc.cancel()
}

func (wc *watchChan) ResultChan() <-chan watch.Event {
	return wc.resultChan
}

// sync tries to retrieve existing data and send them to process.
// The revision to watch will be set to the revision in response.
// All events sent will have isCreated=true
func (wc *watchChan) sync() error {
	if wc.recursive {
		// range
		resp, err := wc.watcher.client.Range(wc.ctx, wc.key, prefixEnd(wc.key))
		if err != nil {
			return err
		}
		wc.initialRev = int64(resp.Header.Revision)
		for _, kv := range resp.Kvs {
			wc.sendEvent(parseKV(kv))
		}
	} else {
		// get
		resp, err := wc.watcher.client.Get(wc.ctx, wc.key)
		if err != nil {
			return err
		}
		wc.initialRev = int64(resp.Header.Revision)
		wc.sendEvent(parseKV(resp.Kv))

	}
	return nil
}

// logWatchChannelErr checks whether the error is about mvcc revision compaction which is regarded as warning
func logWatchChannelErr(err error) {
	if !strings.Contains(err.Error(), "mvcc: required revision has been compacted") {
		klog.Errorf("watch chan error: %v", err)
	} else {
		klog.Warningf("watch chan error: %v", err)
	}
}

// startWatching does:
// - get current objects if initialRev=0; set initialRev to current rev
// - watch on given key and send events to process.
func (wc *watchChan) startWatching(watchClosedCh chan struct{}) {
	if wc.initialRev == 0 {
		if err := wc.sync(); err != nil {
			klog.Errorf("failed to sync with latest state: %v", err)
			wc.sendError(err)
			return
		}
	}
	opts := []client.WatchOption{client.WithRevision(uint64(wc.initialRev + 1))}
	if wc.recursive {
		opts = append(opts, client.WithPrefix())
	}
	// todo: kubebarin当前没开源bookmark实现
	/*
		if wc.progressNotify {
			opts = append(opts, client.WithBookmark())
		}
	*/

	wch := wc.watcher.client.Watch(wc.ctx, wc.key, opts...)
	for wres := range wch {
		if wres.Err() != nil {
			err := wres.Err()
			// If there is an error on server (e.g. compaction), the channel will return it before closed.
			logWatchChannelErr(err)
			wc.sendError(err)
			return
		}

		// todo: kubebarin当前没开源bookmark实现
		/*
			if wres.IsBookmark() {
				wc.sendEvent(progressNotifyEvent(int64(wres.Header.Revision)))
				continue
			}
		*/

		for _, e := range wres.Events {
			parsedEvent, err := parseEvent(e)
			if err != nil {
				logWatchChannelErr(err)
				wc.sendError(err)
				return
			}
			wc.sendEvent(parsedEvent)
		}
	}
	// When we come to this point, it's only possible that client side ends the watch.
	// e.g. cancel the context, close the client.
	// If this watch chan is broken and context isn't cancelled, other goroutines will still hang.
	// We should notify the main thread that this goroutine has exited.
	close(watchClosedCh)
}

// processEvent processes events from etcd watcher and sends results to resultChan.
func (wc *watchChan) processEvent(wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case e := <-wc.incomingEventChan:
			res := wc.transform(e)
			if res == nil {
				continue
			}
			if len(wc.resultChan) == outgoingBufSize {
				klog.V(3).InfoS("Fast watcher, slow processing. Probably caused by slow dispatching events to watchers", "outgoingEvents", outgoingBufSize, "objectType", wc.watcher.objectType)
			}
			// If user couldn't receive results fast enough, we also block incoming events from watcher.
			// Because storing events in local will cause more memory usage.
			// The worst case would be closing the fast watcher.
			select {
			case wc.resultChan <- *res:
			case <-wc.ctx.Done():
				return
			}
		case <-wc.ctx.Done():
			return
		}
	}
}

func (wc *watchChan) filter(obj runtime.Object) bool {
	if wc.internalPred.Empty() {
		return true
	}
	matched, err := wc.internalPred.Matches(obj)
	return err == nil && matched
}

func (wc *watchChan) acceptAll() bool {
	return wc.internalPred.Empty()
}

// transform transforms an event into a result for user if not filtered.
func (wc *watchChan) transform(e *event) (res *watch.Event) {
	curObj, err := wc.prepareObjs(e)
	if err != nil {
		klog.Errorf("failed to prepare current and previous objects: %v", err)
		wc.sendError(err)
		return nil
	}

	switch {
	case e.isProgressNotify:
		if wc.watcher.newFunc == nil {
			return nil
		}
		object := wc.watcher.newFunc()
		if err := wc.watcher.versioner.UpdateObject(object, uint64(e.rev)); err != nil {
			klog.Errorf("failed to propagate object version: %v", err)
			return nil
		}
		res = &watch.Event{
			Type:   watch.Bookmark,
			Object: object,
		}
	case e.isDeleted:
		if !wc.filter(curObj) {
			return nil
		}
		res = &watch.Event{
			Type:   watch.Deleted,
			Object: curObj,
		}
	case e.isCreated:
		if !wc.filter(curObj) {
			return nil
		}
		res = &watch.Event{
			Type:   watch.Added,
			Object: curObj,
		}
	default:
		// todo： 根据preKV判断Event类型
		res = &watch.Event{
			Type:   watch.Modified,
			Object: curObj,
		}
		return res
	}
	return res
}

func transformErrorToEvent(err error) *watch.Event {
	err = interpretWatchError(err)
	if _, ok := err.(apierrors.APIStatus); !ok {
		err = apierrors.NewInternalError(err)
	}
	status := err.(apierrors.APIStatus).Status()
	return &watch.Event{
		Type:   watch.Error,
		Object: &status,
	}
}

func (wc *watchChan) sendError(err error) {
	select {
	case wc.errChan <- err:
	case <-wc.ctx.Done():
	}
}

func (wc *watchChan) sendEvent(e *event) {
	if len(wc.incomingEventChan) == incomingBufSize {
		klog.V(3).InfoS("Fast watcher, slow processing. Probably caused by slow decoding, user not receiving fast, or other processing logic", "incomingEvents", incomingBufSize, "objectType", wc.watcher.objectType)
	}
	select {
	case wc.incomingEventChan <- e:
	case <-wc.ctx.Done():
	}
}

func (wc *watchChan) prepareObjs(e *event) (curObj runtime.Object, err error) {
	if e.isProgressNotify {
		// progressNotify events doesn't contain neither current nor previous object version,
		return nil, nil
	}

	// 与etcd不同，这里无论是delete还是其他操作，都是返回curObj
	// todo: deletion的时候返回preObject
	data, _, err := wc.watcher.transformer.TransformFromStorage(wc.ctx, e.value, authenticatedDataString(e.key))
	if err != nil {
		return nil, err
	}
	curObj, err = decodeObj(wc.watcher.codec, wc.watcher.versioner, data, e.rev)
	if err != nil {
		return nil, err
	}
	return curObj, nil
}

func decodeObj(codec runtime.Codec, versioner storage.Versioner, data []byte, rev int64) (_ runtime.Object, err error) {
	obj, err := runtime.Decode(codec, []byte(data))
	if err != nil {
		if fatalOnDecodeError {
			// catch watch decode error iff we caused it on
			// purpose during a unit test
			defer testingDeferOnDecodeError()
			// we are running in a test environment and thus an
			// error here is due to a coder mistake if the defer
			// does not catch it
			panic(err)
		}
		return nil, err
	}
	// ensure resource version is set on the object we load from etcd
	if err := versioner.UpdateObject(obj, uint64(rev)); err != nil {
		return nil, fmt.Errorf("failure to version api object (%d) %#v: %v", rev, obj, err)
	}
	return obj, nil
}
