package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/valyala/fasthttp"

	"connect"
)

const (
	// _AcceptRcvBuf is the receive buffer set on every accepted connection.
	// Large enough to receive request headers + a max-size body in one shot.
	// SSE connections have this reduced to the kernel minimum after hijack
	// since they receive nothing after the initial GET.
	_AcceptRcvBuf = 4 << 10 // 4 KiB

	// _AcceptSndBuf is the send buffer set on every accepted connection.
	// POST responses are ~300 B; the SSE upgrade response is ~100 B.
	// SSE connections have this raised to _FrameSize after hijack.
	_AcceptSndBuf = 2 << 10 // 2 KiB
)

// sizingListener wraps a net.Listener and sets tight socket buffers on every
// accepted TCP connection before the HTTP layer sees it.
type sizingListener struct {
	net.Listener
}

func (l *sizingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetReadBuffer(_AcceptRcvBuf)  //nolint:errcheck
		tc.SetWriteBuffer(_AcceptSndBuf) //nolint:errcheck
	}
	return c, nil
}

// instanceConfig is the JSON structure stored in the SSM config parameter.
type instanceConfig struct {
	Cert string `json:"cert"` // base64-encoded TLS certificate PEM
	Key  string `json:"key"`  // base64-encoded TLS private key PEM
	ASG  string `json:"asg"`  // Auto Scaling Group name for peer discovery
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	network := flag.String("network", "tcp", "listen network (tcp, tcp4, tcp6)")
	configS3 := flag.String("config-s3", "", "S3 URI for JSON instance config, e.g. s3://bucket/key (enables HTTPS + peer discovery)")
	awsRegion := flag.String("aws-region", "", "AWS region (required when running in environments without IMDSv2, e.g. NanoVMs)")
	nodeURL := flag.String("node-url", "", "this node's base URL for peer routing, e.g. https://node-abc123.example.com")
	zoneName := flag.String("zone-name", "", "DNS zone name used to derive peer node URLs from IPv6 addresses, e.g. peerwave.ai")
	debugAddr := flag.String("debug-addr", "", "optional address for debug/runtime HTTP endpoint, e.g. 127.0.0.1:18090")
	useFastHTTP := flag.Bool("fasthttp", false, "use fasthttp instead of net/http (lower allocations per request)")
	flag.Parse()

	ctx := context.Background()

	if *debugAddr != "" {
		startDebugServer(*debugAddr)
	}

	var cfg instanceConfig
	if *configS3 != "" {
		var err error
		cfg, err = getS3Config(ctx, *configS3, *awsRegion)
		if err != nil {
			log.Fatalf("fetching instance config: %v", err)
		}
	}

	var peerFinder connect.PeerFinder
	if cfg.ASG != "" && *zoneName != "" {
		awsCfg, err := config.LoadDefaultConfig(ctx, awsConfigOpts(*awsRegion)...)
		if err != nil {
			log.Fatalf("loading AWS config for peer finder: %v", err)
		}
		pf := &ec2PeerFinder{
			ec2:      ec2svc.NewFromConfig(awsCfg),
			asgName:  cfg.ASG,
			zoneName: *zoneName,
			scheme:   "https",
		}
		pf.start(ctx)
		peerFinder = pf
	}

	connectCfg := connect.Config{
		PeerFinder: peerFinder,
		NodeURL:    *nodeURL,
	}

	lc := net.ListenConfig{
		Control: listenControl,
	}
	rawLn, err := lc.Listen(ctx, *network, *addr)
	if err != nil {
		log.Fatalf("listen %s %s: %v", *network, *addr, err)
	}
	// Wrap the listener to set tight socket buffers on every accepted connection
	// before the HTTP handshake begins. We know the traffic shape precisely:
	//   rcvbuf=_AcceptRcvBuf: large enough for request headers + a max-size body
	//                         (SDP ~1.5 KB base64, ICE ~300 B, hard cap 4 KB).
	//   sndbuf=_AcceptSndBuf: large enough for any POST response (~300 B) and
	//                         the SSE upgrade response (~100 B). SSE connections
	//                         have their sndbuf raised to _FrameSize after hijack.
	ln := &sizingListener{Listener: rawLn}
	log.Println("Listening on: ", ln.Addr())

	if *useFastHTTP {
		fs := connect.NewFastServer(ctx, connectCfg)
		fhSrv := &fasthttp.Server{
			Handler:            fs.Handler,
			ReadTimeout:        10 * time.Second,
			WriteTimeout:       0,
			IdleTimeout:        60 * time.Second,
			MaxRequestBodySize: 4 << 10, // 4 KiB
			// KeepHijackedConns prevents fasthttp from closing the underlying
			// net.Conn after our SSE hijack handler returns. The hub owns the
			// connection lifetime from that point.
			KeepHijackedConns: true,
		}
		if cfg.Cert != "" {
			tlsCfg, err := buildTLS(cfg.Cert, cfg.Key)
			if err != nil {
				log.Fatalf("building TLS config: %v", err)
			}
			tlsLn := tls.NewListener(ln, tlsCfg)
			log.Println("fasthttp: serving HTTPS")
			if err := fhSrv.Serve(tlsLn); err != nil {
				log.Fatalf("fasthttp serving HTTPS: %v", err)
			}
		} else {
			log.Println("fasthttp: serving HTTP")
			if err := fhSrv.Serve(ln); err != nil {
				log.Fatalf("fasthttp serving: %v", err)
			}
		}
	} else {
		httpSrv := &http.Server{
			Addr:    *addr,
			Handler: connect.NewServer(ctx, connectCfg),
			// Disable HTTP/2: ServeTLS enables it automatically via ALPN, but
			// hijacking (required for SSE) is not available on HTTP/2 streams.
			TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      0,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 10, // 1 KiB
		}
		if cfg.Cert != "" {
			tlsCfg, err := buildTLS(cfg.Cert, cfg.Key)
			if err != nil {
				log.Fatalf("building TLS config: %v", err)
			}
			httpSrv.TLSConfig = tlsCfg
			if err := httpSrv.ServeTLS(ln, "", ""); err != nil {
				log.Fatalf("serving HTTPS: %v\n", err)
			}
		} else {
			if err := httpSrv.Serve(ln); err != nil {
				log.Fatalf("serving: %v\n", err)
			}
		}
	}
	log.Println("server stopped")
}

// awsConfigOpts returns LoadOptions for the given region (empty = auto-detect).
func awsConfigOpts(region string) []func(*config.LoadOptions) error {
	if region == "" {
		return nil
	}
	return []func(*config.LoadOptions) error{config.WithRegion(region)}
}

func getS3Config(ctx context.Context, uri, region string) (instanceConfig, error) {
	var cfg instanceConfig
	awsCfg, err := config.LoadDefaultConfig(ctx, awsConfigOpts(region)...)
	if err != nil {
		return cfg, err
	}
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateEnabled
	})
	if err := loadInstanceConfig(ctx, s3Client, uri, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// loadInstanceConfig fetches the JSON config from an S3 URI (s3://bucket/key)
// and decodes it into cfg.
func loadInstanceConfig(ctx context.Context, client *s3.Client, uri string, cfg *instanceConfig) error {
	uri = strings.TrimPrefix(uri, "s3://")
	idx := strings.IndexByte(uri, '/')
	if idx < 0 {
		return fmt.Errorf("invalid S3 URI: missing key (expected s3://bucket/key)")
	}
	bucket, key := uri[:idx], uri[idx+1:]

	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	defer out.Body.Close()
	return json.NewDecoder(out.Body).Decode(cfg)
}

// buildTLS decodes base64 cert and key PEMs and returns a TLS config.
// Returns nil if either is empty (plain HTTP mode).
func buildTLS(certB64, keyB64 string) (*tls.Config, error) {
	if certB64 == "" {
		return nil, nil
	}

	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, err
	}
	keyPEM, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ec2PeerFinder periodically queries EC2 for all running instances in an ASG
// and exposes their node URLs for pubkey-based routing.
type ec2PeerFinder struct {
	mu       sync.RWMutex
	peers    []string
	ec2      *ec2svc.Client
	asgName  string
	zoneName string
	scheme   string
}

func (f *ec2PeerFinder) Peers() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.peers
}

func (f *ec2PeerFinder) refresh(ctx context.Context) {
	out, err := f.ec2.DescribeInstances(ctx, &ec2svc.DescribeInstancesInput{
		Filters: []types.Filter{
			{Name: aws.String("tag:aws:autoscaling:groupName"), Values: []string{f.asgName}},
			{Name: aws.String("instance-state-name"), Values: []string{"running"}},
		},
	})
	if err != nil {
		log.Printf("peer refresh: describe instances: %v", err)
		return
	}

	var peers []string
	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			for _, iface := range inst.NetworkInterfaces {
				for _, addr := range iface.Ipv6Addresses {
					if addr.Ipv6Address != nil {
						peers = append(peers, ipNodeURL(aws.ToString(addr.Ipv6Address), f.zoneName, f.scheme))
					}
				}
			}
		}
	}

	f.mu.Lock()
	f.peers = peers
	f.mu.Unlock()
	log.Printf("peers refreshed: %v", peers)
}

func (f *ec2PeerFinder) start(ctx context.Context) {
	f.refresh(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				f.refresh(ctx)
			}
		}
	}()
}

// ipNodeURL derives a stable node base URL from an IPv6 address.
// The first 4 bytes of SHA-256(canonical IP) become an 8-char hex prefix,
// matching the hash used by the Cloudflare registration Lambda.
func ipNodeURL(ip, zoneName, scheme string) string {
	canonical := net.ParseIP(ip).String()
	h := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%s://node-%s.%s", scheme, hex.EncodeToString(h[:4]), zoneName)
}

// startDebugServer binds a local-only HTTP server that exposes Go runtime
// memory stats as JSON for sse-memprobe's -server-debug-url flag.
// Listens on addr (e.g. "127.0.0.1:18090") and never serves externally.
func startDebugServer(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux) // registered by net/http/pprof init
	mux.HandleFunc("/debug/runtime", func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Goroutines int    `json:"goroutines"`
			HeapAlloc  uint64 `json:"heap_alloc"`
			HeapSys    uint64 `json:"heap_sys"`
			StackInuse uint64 `json:"stack_inuse"`
			Sys        uint64 `json:"sys"`
		}{
			Goroutines: runtime.NumGoroutine(),
			HeapAlloc:  m.HeapAlloc,
			HeapSys:    m.HeapSys,
			StackInuse: m.StackInuse,
			Sys:        m.Sys,
		})
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("debug server: %v", err)
		}
	}()
	log.Printf("debug server listening on %s", addr)
}
