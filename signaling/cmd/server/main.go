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

// serverConfig is the fully resolved runtime configuration. JSON tags allow it
// to be decoded directly from the S3 cluster config; CLI-only fields use
// json:"-". Priority: defaults → S3 → explicit CLI flags (see getConfig).
type serverConfig struct {
	Cert          string
	Key           string
	ASG           string
	Addr          string
	ClusterURL    string
	ZoneName      string
	ClusterSecret string
	Peers         []string
	Network       string
	AWSRegion     string
}

// staticPeerFinder implements connect.PeerFinder for a fixed peer list.
// OnChange returns a channel that is never written to because the peer set never changes.
type staticPeerFinder struct {
	peers    []*url.URL
	onChange chan struct{}
}

func (f *staticPeerFinder) Peers() []*url.URL         { return f.peers }
func (f *staticPeerFinder) OnChange() <-chan struct{} { return f.onChange }

func getConfig(ctx context.Context) serverConfig {
	// 1. Sensible defaults.
	cfg := serverConfig{
		Addr:    ":8080",
		Network: "tcp",
	}

	// Define flags. Defaults match cfg above so the usage text is accurate, but
	// cfg is the authoritative default — flag values are only applied when the
	// flag was explicitly set on the command line (see flag.Visit below).
	addr := flag.String("addr", cfg.Addr, "listen address")
	network := flag.String("network", cfg.Network, "listen network (tcp, tcp4, tcp6)")
	configS3 := flag.String("config-s3", "", "S3 URI for JSON instance config, e.g. s3://bucket/key")
	awsRegion := flag.String("aws-region", "", "AWS region (required without IMDSv2, e.g. NanoVMs)")
	clusterURL := flag.String("cluster-url", "", "cluster/regional base URL, e.g. https://us-east.example.com")
	clusterSecret := flag.String("cluster-secret", "", "shared HRW hash secret; all nodes must use the same value")
	peers := flag.String("peers", "", "comma-separated static peer base URLs, e.g. http://localhost:8081,http://localhost:8082")
	zoneName := flag.String("zone-name", "", "DNS zone for peer URL derivation, e.g. example.com")
	flag.Parse()

	// 2. Apply S3 config over defaults. json.Decode only sets fields present in
	// the JSON, so absent keys leave the defaults in cfg untouched.
	if *configS3 != "" {
		if err := getS3Config(ctx, *configS3, *awsRegion, &cfg); err != nil {
			log.Fatalf("fetching instance config: %v", err)
		}
	}

	// 3. Explicit CLI flags override S3. flag.Visit only visits flags that were
	// actually set on the command line, leaving S3 values intact for the rest.
	cfg.AWSRegion = *awsRegion // CLI-only; always apply
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = *addr
		case "network":
			cfg.Network = *network
		case "cluster-url":
			cfg.ClusterURL = *clusterURL
		case "cluster-secret":
			cfg.ClusterSecret = *clusterSecret
		case "peers":
			cfg.Peers = strings.Split(*peers, ",")
		case "zone-name":
			cfg.ZoneName = *zoneName
		}
	})

	return cfg
}

// sizingListener wraps a net.Listener and sets tight socket buffers on every
// accepted TCP connection before the HTTP layer sees it.
type sizingListener struct {
	net.Listener
	rcvbuf, sndbuf int
}

func (l *sizingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetReadBuffer(l.rcvbuf)  //nolint:errcheck
		tc.SetWriteBuffer(l.sndbuf) //nolint:errcheck
	}
	return c, nil
}

func main() {
	ctx := context.Background()
	cfg := getConfig(ctx)

	var peerFinder connect.PeerFinder
	switch {
	case cfg.ASG != "" && cfg.ZoneName != "":
		awsCfg, err := config.LoadDefaultConfig(ctx, awsConfigOpts(cfg.AWSRegion)...)
		if err != nil {
			log.Fatalf("loading AWS config for peer finder: %v", err)
		}
		pf := newEC2PeerFinder(ec2svc.NewFromConfig(awsCfg), cfg.ASG, cfg.ZoneName, "https")
		pf.start(ctx)
		peerFinder = pf
	case len(cfg.Peers) > 0:
		peerURLs := make([]*url.URL, 0, len(cfg.Peers))
		for _, p := range cfg.Peers {
			u, err := url.Parse(strings.TrimSpace(p))
			if err != nil {
				log.Fatalf("invalid peer URL %q: %v", p, err)
			}
			peerURLs = append(peerURLs, u)
		}
		peerFinder = &staticPeerFinder{peers: peerURLs, onChange: make(chan struct{})}
	}

	if peerFinder != nil && cfg.ClusterSecret == "" {
		log.Println("warning: -cluster-secret not set; HRW routing uses a zero key (dev mode only)")
	}

	// Determine scheme from TLS config: HTTPS when cert is present, HTTP otherwise.
	scheme := "http"
	if cfg.Cert != "" {
		scheme = "https"
	}

	connectCfg := connect.Config{
		PeerFinder:    peerFinder,
		ClusterSecret: cfg.ClusterSecret,
	}
	if cfg.ZoneName != "" {
		u, err := selfNodeURL(cfg.ZoneName, scheme)
		if err != nil {
			log.Fatalf("detecting node URL: %v", err)
		}
		if u == nil {
			log.Fatalf("no public IPv6 address found on any interface; cannot derive node URL for zone %q", cfg.ZoneName)
		}
		connectCfg.NodeURL = u
		log.Printf("node URL: %s", u)
	}
	if cfg.ClusterURL != "" {
		u, err := url.Parse(cfg.ClusterURL)
		if err != nil {
			log.Fatalf("invalid -cluster-url %q: %v", cfg.ClusterURL, err)
		}
		connectCfg.ClusterURL = u
	}

	lc := net.ListenConfig{Control: listenControl}
	rawLn, err := lc.Listen(ctx, cfg.Network, cfg.Addr)
	if err != nil {
		log.Fatalf("listen %s %s: %v", cfg.Network, cfg.Addr, err)
	}
	var ln net.Listener = &sizingListener{Listener: rawLn, rcvbuf: 4 << 10, sndbuf: 2 << 10}
	log.Println("Listening on:", ln.Addr())

	srv := connect.NewHTTPServer(ctx, connectCfg)
	if cfg.Cert != "" {
		tlsCfg, err := buildTLS(cfg.Cert, cfg.Key)
		if err != nil {
			log.Fatalf("building TLS config: %v", err)
		}
		ln = tls.NewListener(ln, tlsCfg)
	}
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("serving: %v\n", err)
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

func getS3Config(ctx context.Context, uri, region string, cfg *serverConfig) error {
	awsCfg, err := config.LoadDefaultConfig(ctx, awsConfigOpts(region)...)
	if err != nil {
		return err
	}
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateEnabled
	})
	uri = strings.TrimPrefix(uri, "s3://")
	bucket, key, ok := strings.Cut(uri, "/")
	if !ok {
		return fmt.Errorf("invalid S3 URI: missing key (expected s3://bucket/key)")
	}
	out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
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
			ip, err := instanceIP(inst)
			if err != nil {
				log.Printf("peer refresh: instance %s: %v", aws.ToString(inst.InstanceId), err)
				continue
			}
			if ip == nil {
				continue
			}
			u, err := ipNodeURL(ip, f.zoneName, f.scheme)
			if err != nil {
				log.Printf("peer refresh: instance %s: build URL: %v", aws.ToString(inst.InstanceId), err)
				continue
			}
			peers = append(peers, u)
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

// instanceIP returns the first public IPv6 address on the instance, preferring
// the primary ENI (lowest device index). Returns nil, nil if no usable address
// is found.
func instanceIP(inst types.Instance) (net.IP, error) {
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
			return ip, nil
		}
	}
	return nil, nil
}

// ipNodeURL derives a stable node base URL from a public IPv6 address.
// The first 4 bytes of SHA-256(canonical IP string) become an 8-char hex
// prefix, matching the hash used by the Cloudflare registration Lambda.
func ipNodeURL(ip net.IP, zoneName, scheme string) (*url.URL, error) {
	h := sha256.Sum256([]byte(ip.String()))
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
			return ipNodeURL(ip, zoneName, scheme)
		}
	}
	return nil, nil
}
