package main

import (
	"cmp"
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
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

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

// instanceConfig is the full JSON config loaded from S3. Any non-zero field
// overrides the corresponding CLI flag. This allows cluster-wide configuration
// without baking secrets into the binary or launch template.
// Node-specific values (e.g. NodeURL) are derived at runtime from the instance itself.
type instanceConfig struct {
	Cert          string   `json:"cert"`           // base64-encoded TLS certificate PEM
	Key           string   `json:"key"`            // base64-encoded TLS private key PEM
	ASG           string   `json:"asg"`            // Auto Scaling Group name for EC2 peer discovery
	Addr          string   `json:"addr"`           // listen address (overrides -addr)
	ClusterURL    string   `json:"cluster_url"`    // cluster/regional base URL (overrides -cluster-url)
	ZoneName      string   `json:"zone_name"`      // DNS zone for peer URL derivation (overrides -zone-name)
	ClusterSecret string   `json:"cluster_secret"` // shared HRW hash secret (overrides -cluster-secret)
	Peers         []string `json:"peers"`          // static peer list (overrides -peers)
}

// staticPeerFinder implements connect.PeerFinder for a fixed peer list.
// OnChange returns a channel that is never written to because the peer set never changes.
type staticPeerFinder struct {
	peers    []*url.URL
	onChange chan struct{}
}

func (f *staticPeerFinder) Peers() []*url.URL         { return f.peers }
func (f *staticPeerFinder) OnChange() <-chan struct{} { return f.onChange }

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	network := flag.String("network", "tcp", "listen network (tcp, tcp4, tcp6)")
	configS3 := flag.String("config-s3", "", "S3 URI for JSON instance config, e.g. s3://bucket/key (enables HTTPS + peer discovery)")
	awsRegion := flag.String("aws-region", "", "AWS region (required when running in environments without IMDSv2, e.g. NanoVMs)")
	clusterURL := flag.String("cluster-url", "", "cluster/regional base URL, e.g. https://us-east.example.com")
	clusterSecret := flag.String("cluster-secret", "", "shared HRW hash secret; all nodes in the cluster must use the same value")
	peers := flag.String("peers", "", "comma-separated static peer base URLs, e.g. http://localhost:8081,http://localhost:8082")
	zoneName := flag.String("zone-name", "", "DNS zone name used to derive peer node URLs from IPv6 addresses, e.g. peerwave.ai")
	flag.Parse()

	ctx := context.Background()

	var cfg instanceConfig
	if *configS3 != "" {
		var err error
		cfg, err = getS3Config(ctx, *configS3, *awsRegion)
		if err != nil {
			log.Fatalf("fetching instance config: %v", err)
		}
		// S3 config fields override CLI flags when non-zero.
		if cfg.Addr != "" {
			*addr = cfg.Addr
		}
		if cfg.ClusterURL != "" {
			*clusterURL = cfg.ClusterURL
		}
		if cfg.ZoneName != "" {
			*zoneName = cfg.ZoneName
		}
		if cfg.ClusterSecret != "" {
			*clusterSecret = cfg.ClusterSecret
		}
		if len(cfg.Peers) > 0 {
			*peers = strings.Join(cfg.Peers, ",")
		}
	}

	var peerFinder connect.PeerFinder
	switch {
	case cfg.ASG != "" && *zoneName != "":
		awsCfg, err := config.LoadDefaultConfig(ctx, awsConfigOpts(*awsRegion)...)
		if err != nil {
			log.Fatalf("loading AWS config for peer finder: %v", err)
		}
		pf := newEC2PeerFinder(ec2svc.NewFromConfig(awsCfg), cfg.ASG, *zoneName, "https")
		pf.start(ctx)
		peerFinder = pf
	case *peers != "":
		parts := strings.Split(*peers, ",")
		peerURLs := make([]*url.URL, 0, len(parts))
		for _, p := range parts {
			u, err := url.Parse(strings.TrimSpace(p))
			if err != nil {
				log.Fatalf("invalid peer URL %q: %v", p, err)
			}
			peerURLs = append(peerURLs, u)
		}
		peerFinder = &staticPeerFinder{peers: peerURLs, onChange: make(chan struct{})}
	}

	if peerFinder != nil && *clusterSecret == "" {
		log.Println("warning: -cluster-secret not set; HRW routing uses a zero key (dev mode only)")
	}

	// Determine scheme from TLS config: HTTPS when cert is present, HTTP otherwise.
	scheme := "http"
	if cfg.Cert != "" {
		scheme = "https"
	}

	connectCfg := connect.Config{
		PeerFinder:    peerFinder,
		ClusterSecret: *clusterSecret,
	}
	if *zoneName != "" {
		u, err := selfNodeURL(*zoneName, scheme)
		if err != nil {
			log.Fatalf("detecting node URL: %v", err)
		}
		if u == nil {
			log.Fatalf("no public IPv6 address found on any interface; cannot derive node URL for zone %q", *zoneName)
		}
		connectCfg.NodeURL = u
		log.Printf("node URL: %s", u)
	}
	if *clusterURL != "" {
		u, err := url.Parse(*clusterURL)
		if err != nil {
			log.Fatalf("invalid -cluster-url %q: %v", *clusterURL, err)
		}
		connectCfg.ClusterURL = u
	}

	lc := net.ListenConfig{
		Control: listenControl,
	}
	rawLn, err := lc.Listen(ctx, *network, *addr)
	if err != nil {
		log.Fatalf("listen %s %s: %v", *network, *addr, err)
	}

	ln := &sizingListener{Listener: rawLn}
	log.Println("Listening on: ", ln.Addr())

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
	peers    []*url.URL
	onChange chan struct{}
	ec2      *ec2svc.Client
	asgName  string
	zoneName string
	scheme   string
}

func newEC2PeerFinder(client *ec2svc.Client, asgName, zoneName, scheme string) *ec2PeerFinder {
	return &ec2PeerFinder{
		onChange: make(chan struct{}, 1),
		ec2:      client,
		asgName:  asgName,
		zoneName: zoneName,
		scheme:   scheme,
	}
}

func (f *ec2PeerFinder) Peers() []*url.URL {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.peers
}

// OnChange returns a channel that receives an empty signal whenever the set of
// running ASG instances changes. The channel has a buffer of 1; if the consumer
// is slow, intermediate signals are dropped (the consumer calls Peers() for the
// authoritative current list).
func (f *ec2PeerFinder) OnChange() <-chan struct{} { return f.onChange }

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

	var peers []*url.URL
	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			u, err := instanceURL(inst, f.zoneName, f.scheme)
			if err != nil {
				log.Printf("peer refresh: instance %s: %v", aws.ToString(inst.InstanceId), err)
				continue
			}
			if u != nil {
				peers = append(peers, u)
			}
		}
	}
	slices.SortFunc(peers, func(a, b *url.URL) int { return strings.Compare(a.Host, b.Host) })

	f.mu.Lock()
	changed := !slices.EqualFunc(f.peers, peers, func(a, b *url.URL) bool { return a.Host == b.Host })
	f.peers = peers
	f.mu.Unlock()

	log.Printf("peers refreshed: %v", peers)
	if changed {
		// Non-blocking send: if the buffer is full the consumer hasn't processed
		// the last notification yet; it will call Peers() when it does.
		select {
		case f.onChange <- struct{}{}:
		default:
		}
	}
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

// instanceURL returns the peer URL for the first public IPv6 address found on
// the instance's network interfaces, ordered by device index so the primary ENI
// (index 0) is preferred. Returns nil, nil if the instance has no usable address.
func instanceURL(inst types.Instance, zoneName, scheme string) (*url.URL, error) {
	ifaces := make([]types.InstanceNetworkInterface, len(inst.NetworkInterfaces))
	copy(ifaces, inst.NetworkInterfaces)
	slices.SortFunc(ifaces, func(a, b types.InstanceNetworkInterface) int {
		ai, bi := int32(0), int32(0)
		if a.Attachment != nil && a.Attachment.DeviceIndex != nil {
			ai = *a.Attachment.DeviceIndex
		}
		if b.Attachment != nil && b.Attachment.DeviceIndex != nil {
			bi = *b.Attachment.DeviceIndex
		}
		return cmp.Compare(ai, bi)
	})
	for _, iface := range ifaces {
		for _, addr := range iface.Ipv6Addresses {
			if addr.Ipv6Address == nil {
				continue
			}
			ip := net.ParseIP(aws.ToString(addr.Ipv6Address))
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			return ipNodeURL(aws.ToString(addr.Ipv6Address), zoneName, scheme)
		}
	}
	return nil, nil
}

// ipNodeURL derives a stable node base URL from an IPv6 address.
// The first 4 bytes of SHA-256(canonical IP) become an 8-char hex prefix,
// matching the hash used by the Cloudflare registration Lambda.
func ipNodeURL(ip, zoneName, scheme string) (*url.URL, error) {
	canonical := net.ParseIP(ip).String()
	h := sha256.Sum256([]byte(canonical))
	return url.Parse(fmt.Sprintf("%s://node-%s.%s", scheme, hex.EncodeToString(h[:4]), zoneName))
}

// selfNodeURL finds this node's base URL by scanning local network interfaces
// for a public IPv6 address and deriving the URL via ipNodeURL. Interfaces are
// iterated in system order; the first usable address wins. Returns nil, nil if
// no suitable address is found.
func selfNodeURL(zoneName, scheme string) (*url.URL, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			// IPv6 only: To4() returns non-nil for IPv4 and IPv4-mapped addresses.
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			return ipNodeURL(ip.String(), zoneName, scheme)
		}
	}
	return nil, nil
}
