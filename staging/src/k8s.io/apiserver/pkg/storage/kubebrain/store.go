package kubebrain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"

	rpc "github.com/kubewharf/kubebrain-client/api/v2rpc"
	"github.com/kubewharf/kubebrain-client/client"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/klog/v2"

	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/value"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

const (
	// maxLimit is a maximum page limit increase used when fetching objects from etcd.
	// This limit is used only for increasing page size by kube-apiserver. If request
	// specifies larger limit initially, it won't be changed.
	maxLimit = 10000
)

// authenticate the stored data. This does not defend against reuse of previously
// encrypted values under the same key, but will prevent an attacker from using an
// encrypted value from a different key. A stronger authenticated data segment would
// include the etcd3 Version field (which is incremented on each write to a key and
// reset when the key is deleted), but an attacker with write access to etcd can
// force deletion and recreation of keys to weaken that angle.
type authenticatedDataString string

// AuthenticatedData implements the value.Context interface.
func (d authenticatedDataString) AuthenticatedData() []byte {
	return []byte(string(d))
}

var noPrefixEnd = []byte{0}
var _ storage.Interface = &store{}

type store struct {
	client              client.Client
	codec               runtime.Codec
	versioner           storage.Versioner
	transformer         value.Transformer
	pathPrefix          string
	groupResource       schema.GroupResource
	groupResourceString string
	watcher             *watcher
	pagingEnabled       bool
}

type objState struct {
	obj   runtime.Object
	meta  *storage.ResponseMeta
	rev   int64
	data  []byte
	stale bool
}

func New(c client.Client, codec runtime.Codec, newFunc func() runtime.Object, prefix string, groupResource schema.GroupResource, transformer value.Transformer, pagingEnabled bool) storage.Interface {
	return newStore(c, codec, newFunc, prefix, groupResource, transformer, pagingEnabled)
}

func newStore(c client.Client, codec runtime.Codec, newFunc func() runtime.Object, prefix string, groupResource schema.GroupResource, transformer value.Transformer, pagingEnabled bool) *store {
	versioner := storage.APIObjectVersioner{}
	// for compatibility with etcd2 impl.
	// no-op for default prefix of '/registry'.
	// keeps compatibility with etcd2 impl for custom prefixes that don't start with '/'
	pathPrefix := path.Join("/", prefix)
	if !strings.HasSuffix(pathPrefix, "/") {
		// Ensure the pathPrefix ends in "/" here to simplify key concatenation later.
		pathPrefix += "/"
	}
	result := &store{
		client:              c,
		codec:               codec,
		versioner:           versioner,
		transformer:         transformer,
		pagingEnabled:       pagingEnabled,
		pathPrefix:          pathPrefix,
		groupResource:       groupResource,
		groupResourceString: groupResource.String(),
		watcher:             newWatcher(c, codec, newFunc, versioner, transformer),
	}
	return result
}

// Versioner implements storage.Interface.Versioner.
func (s *store) Versioner() storage.Versioner {
	return s.versioner
}
func (s *store) Get(ctx context.Context, key string, opts storage.GetOptions, out runtime.Object) error {
	preparedKey, err := s.prepareKey(key)
	if err != nil {
		return err
	}

	minimumResourceVersion, err := s.versioner.ParseResourceVersion(opts.ResourceVersion)
	if err != nil {
		return apierrors.NewBadRequest(fmt.Sprintf("invalid resource version: %v", err))
	}
	resp, err := s.client.Get(ctx, preparedKey, client.WithRevision(minimumResourceVersion))
	if err != nil {
		return err
	}
	// 版本校验
	if err := s.validateMinimumResourceVersion(opts.ResourceVersion, resp.Header.Revision); err != nil {
		return err
	}

	if resp.Kv == nil {
		if opts.IgnoreNotFound {
			return runtime.SetZeroValue(out)
		}
		return storage.NewKeyNotFoundError(preparedKey, 0)
	}
	kv := resp.Kv
	data, _, err := s.transformer.TransformFromStorage(ctx, kv.Value, authenticatedDataString(preparedKey))
	if err != nil {
		return storage.NewInternalError(err.Error())
	}

	return decode(s.codec, s.versioner, data, out, int64(kv.Revision))
}

func (s *store) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	preparedKey, err := s.prepareKey(key)
	if err != nil {
		return err
	}

	// resourceVersion 不应被设置
	if version, err := s.versioner.ObjectResourceVersion(obj); err == nil && version != 0 {
		return errors.New("resourceVersion should not be set on objects to be created")
	}

	// 存储前预处理
	if err := s.versioner.PrepareObjectForStorage(obj); err != nil {
		return fmt.Errorf("PrepareObjectForStorage failed: %v", err)
	}

	// 编码对象
	data, err := runtime.Encode(s.codec, obj)
	if err != nil {
		return err
	}

	// 加密/转换
	newData, err := s.transformer.TransformToStorage(ctx, data, authenticatedDataString(preparedKey))
	if err != nil {
		return storage.NewInternalError(err.Error())
	}

	resp, err := s.client.Create(ctx, preparedKey, string(newData), client.WithTTL(int64(ttl)))
	if err != nil {
		return err
	}

	if !resp.Succeeded {
		return storage.NewKeyExistsError(preparedKey, int64(resp.Header.Revision))
	}

	// 如果 out 不为 nil，解码写入 out
	if out != nil {
		err = decode(s.codec, s.versioner, data, out, int64(resp.Header.Revision))
		return err
	}
	return nil
}
func (s *store) Delete(
	ctx context.Context, key string, out runtime.Object, preconditions *storage.Preconditions,
	validateDeletion storage.ValidateObjectFunc, cachedExistingObject runtime.Object) error {
	preparedKey, err := s.prepareKey(key)
	if err != nil {
		return err
	}
	v, err := conversion.EnforcePtr(out)
	if err != nil {
		return fmt.Errorf("unable to convert output object to pointer: %v", err)
	}

	getCurrentState := func() (*objState, error) {
		resp, err := s.client.Get(ctx, preparedKey)
		if err != nil {
			return nil, err
		}
		return s.getState(ctx, resp.Kv, key, v, false)
	}

	var origState *objState
	var origStateIsCurrent bool
	var errGet error
	if cachedExistingObject != nil {
		origState, errGet = s.getStateFromObject(cachedExistingObject)
	} else {
		origState, errGet = getCurrentState()
		origStateIsCurrent = true
	}
	if errGet != nil {
		return errGet
	}

	for {
		// 校验 preconditions
		if preconditions != nil {
			if err := preconditions.Check(preparedKey, origState.obj); err != nil {
				if origStateIsCurrent {
					return err
				}
				cachedRev := origState.rev
				cachedUpdateErr := err
				origState, err = getCurrentState()
				if err != nil {
					return err
				}
				origStateIsCurrent = true
				if cachedRev == origState.rev {
					return cachedUpdateErr
				}
				continue
			}
		}
		// 校验 validateDeletion
		if err := validateDeletion(ctx, origState.obj); err != nil {
			if origStateIsCurrent {
				return err
			}
			cachedRev := origState.rev
			cachedUpdateErr := err
			origState, err = getCurrentState()
			if err != nil {
				return err
			}
			origStateIsCurrent = true
			if cachedRev == origState.rev {
				return cachedUpdateErr
			}
			continue
		}

		// 尝试删除，带 revision
		delResp, err := s.client.Delete(ctx, preparedKey, client.WithRevision(uint64(origState.rev)))
		if err != nil {
			return err
		}
		if !delResp.Succeeded {
			kv := delResp.Kv
			if kv == nil {
				return storage.NewKeyNotFoundError(preparedKey, 0)
			}
			origState, err = s.getState(ctx, kv, key, v, false)
			if err != nil {
				return err
			}
			origStateIsCurrent = true
			continue
		}
		// 删除成功，返回被删除对象内容
		return decode(s.codec, s.versioner, origState.data, out, origState.rev)
	}
}

func (s *store) Count(key string) (int64, error) {
	preparedKey, err := s.prepareKey(key)
	if err != nil {
		return 0, err
	}

	// We need to make sure the key ended with "/" so that we only get children "directories".
	// e.g. if we have key "/a", "/a/b", "/ab", getting keys with prefix "/a" will return all three,
	// while with prefix "/a/" will return only "/a/b" which is the correct answer.
	if !strings.HasSuffix(preparedKey, "/") {
		preparedKey += "/"
	}

	countResp, err := s.client.Count(context.Background(), preparedKey, prefixEnd(preparedKey))
	if err != nil {
		return 0, err
	}
	return int64(countResp.Count), nil
}

// Watch implements storage.Interface.Watch.
func (s *store) Watch(ctx context.Context, key string, opts storage.ListOptions) (watch.Interface, error) {
	preparedKey, err := s.prepareKey(key)
	if err != nil {
		return nil, err
	}
	rev, err := s.versioner.ParseResourceVersion(opts.ResourceVersion)
	if err != nil {
		return nil, err
	}
	return s.watcher.Watch(ctx, preparedKey, int64(rev), opts.Recursive, opts.ProgressNotify, opts.Predicate)
}

// GuaranteedUpdate implements storage.Interface.GuaranteedUpdate.
func (s *store) GuaranteedUpdate(
	ctx context.Context, key string, destination runtime.Object, ignoreNotFound bool,
	preconditions *storage.Preconditions, tryUpdate storage.UpdateFunc, cachedExistingObject runtime.Object) error {
	preparedKey, err := s.prepareKey(key)
	if err != nil {
		return err
	}

	v, err := conversion.EnforcePtr(destination)
	if err != nil {
		return fmt.Errorf("unable to convert output object to pointer: %v", err)
	}

	getCurrentState := func() (*objState, error) {
		resp, err := s.client.Get(ctx, preparedKey)
		if err != nil {
			return nil, err
		}
		return s.getState(ctx, resp.Kv, key, v, false)
	}

	var origState *objState
	var origStateIsCurrent bool
	if cachedExistingObject != nil {
		origState, err = s.getStateFromObject(cachedExistingObject)
	} else {
		origState, err = getCurrentState()
		origStateIsCurrent = true
	}
	if err != nil {
		return err
	}

	transformContext := authenticatedDataString(preparedKey)
	for {
		// 校验 preconditions
		if err := preconditions.Check(preparedKey, origState.obj); err != nil {
			if origStateIsCurrent {
				return err
			}
			origState, err = getCurrentState()
			if err != nil {
				return err
			}
			origStateIsCurrent = true
			continue
		}

		// 生成新对象
		ret, ttl, err := s.updateState(origState, tryUpdate)
		if err != nil {
			if origStateIsCurrent {
				return err
			}
			cachedRev := origState.rev
			cachedUpdateErr := err
			origState, err = getCurrentState()
			if err != nil {
				return err
			}
			origStateIsCurrent = true
			if cachedRev == origState.rev {
				return cachedUpdateErr
			}
			continue
		}

		// 编码
		data, err := runtime.Encode(s.codec, ret)
		if err != nil {
			return err
		}
		// 数据未变短路
		if !origState.stale && bytes.Equal(data, origState.data) {
			if !origStateIsCurrent {
				origState, err = getCurrentState()
				if err != nil {
					return err
				}
				origStateIsCurrent = true
				if !bytes.Equal(data, origState.data) {
					continue
				}
			}
			if !origState.stale {
				return decode(s.codec, s.versioner, origState.data, destination, origState.rev)
			}
		}

		// 加密/转换
		newData, err := s.transformer.TransformToStorage(ctx, data, transformContext)
		if err != nil {
			return storage.NewInternalError(err.Error())
		}

		// update，带 revision
		resp, err := s.client.Update(ctx, preparedKey, string(newData), uint64(origState.rev), client.WithTTL(int64(ttl)))
		if err != nil {
			return err
		}
		if !resp.Succeeded {
			// 版本冲突，重试
			kv := resp.Kv
			origState, err = s.getState(ctx, kv, preparedKey, v, ignoreNotFound)
			if err != nil {
				return err
			}
			origStateIsCurrent = true
			continue
		}
		// 成功，decode 到 destination
		return decode(s.codec, s.versioner, data, destination, int64(resp.Header.Revision))
	}
}

func (s *store) updateState(st *objState, userUpdate storage.UpdateFunc) (runtime.Object, uint64, error) {
	ret, ttlPtr, err := userUpdate(st.obj, *st.meta)
	if err != nil {
		return nil, 0, err
	}

	if err := s.versioner.PrepareObjectForStorage(ret); err != nil {
		return nil, 0, fmt.Errorf("PrepareObjectForStorage failed: %v", err)
	}
	var ttl uint64
	if ttlPtr != nil {
		ttl = *ttlPtr
	}
	return ret, ttl, nil
}

// GetList implements storage.Interface.GetList.
func (s *store) GetList(ctx context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	preparedKey, err := s.prepareKey(key)
	if err != nil {
		return err
	}
	recursive := opts.Recursive
	resourceVersion := opts.ResourceVersion
	match := opts.ResourceVersionMatch
	pred := opts.Predicate

	listPtr, err := meta.GetItemsPtr(listObj)
	if err != nil {
		return err
	}
	v, err := conversion.EnforcePtr(listPtr)
	if err != nil || v.Kind() != reflect.Slice {
		return fmt.Errorf("need ptr to slice: %v", err)
	}

	if recursive && !strings.HasSuffix(preparedKey, "/") {
		preparedKey += "/"
	}
	keyPrefix := preparedKey

	// 处理分页、limit、continue
	limit := pred.Limit
	paging := s.pagingEnabled && limit > 0

	newItemFunc := getNewItemFunc(listObj, v)

	var fromRV *uint64
	if len(resourceVersion) > 0 {
		parsedRV, err := s.versioner.ParseResourceVersion(resourceVersion)
		if err != nil {
			return apierrors.NewBadRequest(fmt.Sprintf("invalid resource version: %v", err))
		}
		fromRV = &parsedRV
	}

	var returnedRV, continueRV, withRev int64
	var continueKey string
	var rangeEnd string
	switch {
	case recursive && s.pagingEnabled && len(pred.Continue) > 0:
		// 解析 continue token
		continueKey, continueRV, err = storage.DecodeContinue(pred.Continue, keyPrefix)
		if err != nil {
			return apierrors.NewBadRequest(fmt.Sprintf("invalid continue token: %v", err))
		}
		if len(resourceVersion) > 0 && resourceVersion != "0" {
			return apierrors.NewBadRequest("specifying resource version is not allowed when using continue")
		}
		rangeEnd = prefixEnd(keyPrefix)
		preparedKey = continueKey
		if continueRV > 0 {
			withRev = continueRV
			returnedRV = continueRV
		}
	case recursive && s.pagingEnabled && pred.Limit > 0:
		if fromRV != nil {
			switch match {
			case metav1.ResourceVersionMatchNotOlderThan:
				// 事后校验
			case metav1.ResourceVersionMatchExact:
				returnedRV = int64(*fromRV)
				withRev = returnedRV
			case "":
				if *fromRV > 0 {
					returnedRV = int64(*fromRV)
					withRev = returnedRV
				}
			default:
				return fmt.Errorf("unknown ResourceVersionMatch value: %v", match)
			}
		}
		rangeEnd = prefixEnd(keyPrefix)
	default:
		if fromRV != nil {
			switch match {
			case metav1.ResourceVersionMatchNotOlderThan:
			case metav1.ResourceVersionMatchExact:
				returnedRV = int64(*fromRV)
				withRev = returnedRV
			case "":
			default:
				return fmt.Errorf("unknown ResourceVersionMatch value: %v", match)
			}
		}
		if recursive {
			rangeEnd = prefixEnd(keyPrefix)
		}
	}

	// loop until we have filled the requested limit from etcd or there are no more results
	var lastKey []byte
	var hasMore bool
	var numFetched int
	var numEvald int
	var kvs []*rpc.KeyValue
	var responseHeader *rpc.ResponseHeader
	var count int64
	for {
		if rangeEnd != "" {
			opts := []client.RangeOption{}
			if withRev != 0 {
				opts = append(opts, client.WithRevision(uint64(withRev)))
			}
			if limit > 0 {
				opts = append(opts, client.WithLimit(limit))
			}
			resp, err := s.client.Range(ctx, preparedKey, rangeEnd, opts...)
			if err != nil {
				return interpretListError(err, len(pred.Continue) > 0, continueKey, keyPrefix)
			}
			kvs = resp.Kvs
			hasMore = resp.More
			responseHeader = resp.Header
		} else {
			opts := []client.GetOption{}
			if withRev != 0 {
				opts = append(opts, client.WithRevision(uint64(withRev)))
			}
			resp, err := s.client.Get(ctx, preparedKey, opts...)
			if err != nil {
				return interpretListError(err, len(pred.Continue) > 0, continueKey, keyPrefix)
			}
			kvs = append([]*rpc.KeyValue{}, resp.Kv)
			hasMore = false
			responseHeader = resp.Header
		}
		numFetched += len(kvs)
		if err = s.validateMinimumResourceVersion(resourceVersion, responseHeader.Revision); err != nil {
			return err
		}
		if len(kvs) == 0 && hasMore {
			return fmt.Errorf("no results were found, but etcd indicated there were more values remaining")
		}
		// avoid small allocations for the result slice, since this can be called in many
		// different contexts and we don't know how significantly the result will be filtered
		if pred.Empty() {
			growSlice(v, len(kvs))
		} else {
			growSlice(v, 2048, len(kvs))
		}

		// take items from the response until the bucket is full, filtering as we go
		for i, kv := range kvs {
			if paging && int64(v.Len()) >= pred.Limit {
				hasMore = true
				break
			}
			lastKey = kv.Key

			data, _, err := s.transformer.TransformFromStorage(ctx, kv.Value, authenticatedDataString(kv.Key))
			if err != nil {
				return storage.NewInternalErrorf("unable to transform key %q: %v", kv.Key, err)
			}

			if err := appendListItem(v, data, kv.Revision, pred, s.codec, s.versioner, newItemFunc); err != nil {
				return err
			}
			numEvald++

			// free kv early. Long lists can take O(seconds) to decode.
			kvs[i] = nil
		}

		// indicate to the client which resource version was returned
		if returnedRV == 0 {
			returnedRV = int64(responseHeader.Revision)
		}

		// no more results remain or we didn't request paging
		if !hasMore || !paging {
			break
		}
		// we're paging but we have filled our bucket
		if int64(v.Len()) >= pred.Limit {
			break
		}

		if limit < maxLimit {
			// We got incomplete result due to field/label selector dropping the object.
			// Double page size to reduce total number of calls to etcd.
			limit *= 2
			if limit > maxLimit {
				limit = maxLimit
			}
		}
		preparedKey = string(lastKey) + "\x00"
		if withRev == 0 {
			withRev = returnedRV
		}
	}

	// instruct the client to begin querying from immediately after the last key we returned
	// we never return a key that the client wouldn't be allowed to see
	if hasMore {
		// we want to start immediately after the last key
		next, err := storage.EncodeContinue(string(lastKey)+"\x00", keyPrefix, returnedRV)
		if err != nil {
			return err
		}
		var remainingItemCount *int64
		// getResp.Count counts in objects that do not match the pred.
		// Instead of returning inaccurate count for non-empty selectors, we return nil.
		// Only set remainingItemCount if the predicate is empty.
		if utilfeature.DefaultFeatureGate.Enabled(features.RemainingItemCount) {
			if pred.Empty() {
				c := int64(count - pred.Limit)
				remainingItemCount = &c
			}
		}
		return s.versioner.UpdateList(listObj, uint64(returnedRV), next, remainingItemCount)
	}

	// no continuation
	return s.versioner.UpdateList(listObj, uint64(returnedRV), "", nil)
}

// prefixEnd用于Count方法里获取endKey，官方的CountOption没有提供
func prefixEnd(p string) string {
	prefix := []byte(p)
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] < 0xff {
			end[i] = end[i] + 1
			end = end[:i+1]
			return string(end)
		}
	}
	// next prefix does not exist (e.g., 0xffff);
	// default to WithFromKey policy
	return string(noPrefixEnd)
}

func (s *store) getStateFromObject(obj runtime.Object) (*objState, error) {
	state := &objState{
		obj:  obj,
		meta: &storage.ResponseMeta{},
	}

	rv, err := s.versioner.ObjectResourceVersion(obj)
	if err != nil {
		return nil, fmt.Errorf("couldn't get resource version: %v", err)
	}
	state.rev = int64(rv)
	state.meta.ResourceVersion = uint64(state.rev)

	// Compute the serialized form - for that we need to temporarily clean
	// its resource version field (those are not stored in etcd).
	if err := s.versioner.PrepareObjectForStorage(obj); err != nil {
		return nil, fmt.Errorf("PrepareObjectForStorage failed: %v", err)
	}
	state.data, err = runtime.Encode(s.codec, obj)
	if err != nil {
		return nil, err
	}
	if err := s.versioner.UpdateObject(state.obj, uint64(rv)); err != nil {
		klog.Errorf("failed to update object version: %v", err)
	}
	return state, nil
}

func (s *store) getState(ctx context.Context, respKV *rpc.KeyValue, key string, v reflect.Value, ignoreNotFound bool) (*objState, error) {
	state := &objState{
		meta: &storage.ResponseMeta{},
	}

	if u, ok := v.Addr().Interface().(runtime.Unstructured); ok {
		state.obj = u.NewEmptyInstance()
	} else {
		state.obj = reflect.New(v.Type()).Interface().(runtime.Object)
	}

	if respKV == nil {
		if !ignoreNotFound {
			return nil, storage.NewKeyNotFoundError(key, 0)
		}
		if err := runtime.SetZeroValue(state.obj); err != nil {
			return nil, err
		}
	} else {
		data, stale, err := s.transformer.TransformFromStorage(ctx, respKV.Value, authenticatedDataString(key))
		if err != nil {
			return nil, storage.NewInternalError(err.Error())
		}
		state.rev = int64(respKV.Revision)
		state.meta.ResourceVersion = uint64(state.rev)
		state.data = data
		state.stale = stale
		if err := decode(s.codec, s.versioner, state.data, state.obj, state.rev); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (s *store) prepareKey(key string) (string, error) {
	if key == ".." ||
		strings.HasPrefix(key, "../") ||
		strings.HasSuffix(key, "/..") ||
		strings.Contains(key, "/../") {
		return "", fmt.Errorf("invalid key: %q", key)
	}
	if key == "." ||
		strings.HasPrefix(key, "./") ||
		strings.HasSuffix(key, "/.") ||
		strings.Contains(key, "/./") {
		return "", fmt.Errorf("invalid key: %q", key)
	}
	if key == "" || key == "/" {
		return "", fmt.Errorf("empty key: %q", key)
	}
	// We ensured that pathPrefix ends in '/' in construction, so skip any leading '/' in the key now.
	startIndex := 0
	if key[0] == '/' {
		startIndex = 1
	}
	return s.pathPrefix + key[startIndex:], nil
}

// validateMinimumResourceVersion returns a 'too large resource' version error when the provided minimumResourceVersion is
// greater than the most recent actualRevision available from storage.
func (s *store) validateMinimumResourceVersion(minimumResourceVersion string, actualRevision uint64) error {
	if minimumResourceVersion == "" {
		return nil
	}
	minimumRV, err := s.versioner.ParseResourceVersion(minimumResourceVersion)
	if err != nil {
		return apierrors.NewBadRequest(fmt.Sprintf("invalid resource version: %v", err))
	}
	// Enforce the storage.Interface guarantee that the resource version of the returned data
	// "will be at least 'resourceVersion'".
	if minimumRV > actualRevision {
		return storage.NewTooLargeResourceVersionError(minimumRV, actualRevision, 0)
	}
	return nil
}

// decode decodes value of bytes into object. It will also set the object resource version to rev.
// On success, objPtr would be set to the object.
func decode(codec runtime.Codec, versioner storage.Versioner, value []byte, objPtr runtime.Object, rev int64) error {
	if _, err := conversion.EnforcePtr(objPtr); err != nil {
		return fmt.Errorf("unable to convert output object to pointer: %v", err)
	}
	_, _, err := codec.Decode(value, nil, objPtr)
	if err != nil {
		return err
	}
	// being unable to set the version does not prevent the object from being extracted
	if err := versioner.UpdateObject(objPtr, uint64(rev)); err != nil {
		klog.Errorf("failed to update object version: %v", err)
	}
	return nil
}

// growSlice takes a slice value and grows its capacity up
// to the maximum of the passed sizes or maxCapacity, whichever
// is smaller. Above maxCapacity decisions about allocation are left
// to the Go runtime on append. This allows a caller to make an
// educated guess about the potential size of the total list while
// still avoiding overly aggressive initial allocation. If sizes
// is empty maxCapacity will be used as the size to grow.
func growSlice(v reflect.Value, maxCapacity int, sizes ...int) {
	cap := v.Cap()
	max := cap
	for _, size := range sizes {
		if size > max {
			max = size
		}
	}
	if len(sizes) == 0 || max > maxCapacity {
		max = maxCapacity
	}
	if max <= cap {
		return
	}
	if v.Len() > 0 {
		extra := reflect.MakeSlice(v.Type(), v.Len(), max)
		reflect.Copy(extra, v)
		v.Set(extra)
	} else {
		extra := reflect.MakeSlice(v.Type(), 0, max)
		v.Set(extra)
	}
}

// appendListItem decodes and appends the object (if it passes filter) to v, which must be a slice.
func appendListItem(v reflect.Value, data []byte, rev uint64, pred storage.SelectionPredicate, codec runtime.Codec, versioner storage.Versioner, newItemFunc func() runtime.Object) error {
	obj, _, err := codec.Decode(data, nil, newItemFunc())
	if err != nil {
		return err
	}
	// being unable to set the version does not prevent the object from being extracted
	if err := versioner.UpdateObject(obj, rev); err != nil {
		klog.Errorf("failed to update object version: %v", err)
	}
	if matched, err := pred.Matches(obj); err == nil && matched {
		v.Set(reflect.Append(v, reflect.ValueOf(obj).Elem()))
	}
	return nil
}

func getNewItemFunc(listObj runtime.Object, v reflect.Value) func() runtime.Object {
	// For unstructured lists with a target group/version, preserve the group/version in the instantiated list items
	if unstructuredList, isUnstructured := listObj.(*unstructured.UnstructuredList); isUnstructured {
		if apiVersion := unstructuredList.GetAPIVersion(); len(apiVersion) > 0 {
			return func() runtime.Object {
				return &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": apiVersion}}
			}
		}
	}

	// Otherwise just instantiate an empty item
	elem := v.Type().Elem()
	return func() runtime.Object {
		return reflect.New(elem).Interface().(runtime.Object)
	}
}
