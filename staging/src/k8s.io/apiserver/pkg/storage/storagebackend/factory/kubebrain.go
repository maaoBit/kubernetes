package factory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	"google.golang.org/grpc/status"

	"github.com/kubewharf/kubebrain-client/client"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/kubebrain"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/klog/v2"
)

// TLSConfig holds kubebrain client TLS配置
type TLSConfig struct {
	CertFile           string // 客户端证书
	KeyFile            string // 客户端私钥
	CAFile             string // 根CA
	ServerName         string // 服务器名称
	InsecureSkipVerify bool   // 跳过证书校验
}

// NewTLSConfig 根据TLSConfig生成*tls.Config
func NewTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ServerName:         cfg.ServerName,
	}

	// 加载客户端证书
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// 加载CA
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA cert")
		}
		tlsCfg.RootCAs = caPool
	}

	return tlsCfg, nil
}

// 创建 kubebrain storage.Interface 实例
func newKubebrainStorage(c storagebackend.ConfigForResource, newFunc func() runtime.Object) (storage.Interface, DestroyFunc, error) {
	// 创建 kubebrain client
	kbClient, err := newKubebrainClient(c.Transport)
	if err != nil {
		return nil, nil, err
	}
	// no need compact, see github.com/kubewharf/kubebrain/pkg/server/brain/server.go compactLoop()
	// todo: metrics, opentelemetry, APIServerTracing 待完善
	transformer := c.Transformer
	if transformer == nil {
		transformer = value.IdentityTransformer
	}

	store := kubebrain.New(
		kbClient,
		c.Codec,
		newFunc,
		c.Prefix,
		c.GroupResource,
		transformer,
		c.Paging,
	)

	var once sync.Once
	destroyFunc := func() {
		once.Do(func() {
			kbClient.Close()
		})
	}
	return store, destroyFunc, nil
}

// 创建 kubebrain client
func newKubebrainClient(c storagebackend.TransportConfig) (client.Client, error) {
	tlsConfig := TLSConfig{
		CAFile:   c.TrustedCAFile,
		CertFile: c.CertFile,
		KeyFile:  c.KeyFile,
	}
	tls, err := NewTLSConfig(tlsConfig)
	if err != nil {
		return nil, err
	}
	if len(c.CertFile) == 0 && len(c.KeyFile) == 0 && len(c.TrustedCAFile) == 0 {
		tls = nil
	}
	return client.NewClient(client.Config{
		Endpoints: c.ServerList,
		TLS:       tls,
		// todo: 调整
		LogLevel: 2,
	})
}

// kubebrain 健康检查
func newKubebrainHealthCheck(c storagebackend.Config, stopCh <-chan struct{}) (func() error, error) {
	timeout := storagebackend.DefaultHealthcheckTimeout
	if c.HealthcheckTimeout != time.Duration(0) {
		timeout = c.HealthcheckTimeout
	}
	return newKubebrainCheck(c, timeout, stopCh)
}

// kubebrain 就绪检查
func newKubebrainReadyCheck(c storagebackend.Config, stopCh <-chan struct{}) (func() error, error) {
	timeout := storagebackend.DefaultReadinessTimeout
	if c.ReadycheckTimeout != time.Duration(0) {
		timeout = c.ReadycheckTimeout
	}
	return newKubebrainCheck(c, timeout, stopCh)
}

// 健康/就绪检查通用实现
func newKubebrainCheck(c storagebackend.Config, timeout time.Duration, stopCh <-chan struct{}) (func() error, error) {
	lock := sync.Mutex{}
	var kbClient client.Client
	clientErr := fmt.Errorf("kubebrain client connection not yet established")

	go func() {
		for {
			select {
			case <-stopCh:
				lock.Lock()
				if kbClient != nil {
					kbClient.Close()
				}
				lock.Unlock()
				return
			default:
			}
			newClient, err := newKubebrainClient(c.Transport)
			lock.Lock()
			if err != nil {
				clientErr = err
			} else {
				kbClient = newClient
				clientErr = nil
				lock.Unlock()
				return
			}
			lock.Unlock()
			time.Sleep(time.Second)
		}
	}()
	// Close the client on shutdown.
	go func() {
		defer utilruntime.HandleCrash()
		<-stopCh

		lock.Lock()
		defer lock.Unlock()
		if kbClient != nil {
			kbClient.Close()
			clientErr = fmt.Errorf("server is shutting down")
		}
	}()

	return func() error {
		lock.Lock()
		defer lock.Unlock()
		if clientErr != nil {
			return clientErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		// 这里用一个健康 key 检查 kubebrain 可用性
		_, err := kbClient.Get(ctx, path.Join("/", c.Prefix, "health"))
		if err == nil {
			return nil
		}
		st, ok := status.FromError(err)
		if ok {
			klog.Errorf("gRPC code: %w", st.Code())
			klog.Errorf("gRPC message: %w", st.Message())
		}
		return fmt.Errorf("error getting data from kubebrain: %w", err)
	}, nil
}
