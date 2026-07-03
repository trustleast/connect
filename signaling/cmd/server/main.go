package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"connect"
)

type serverConfig struct {
	Cert       string
	Key        string
	ASG        string
	Addr       string
	Network    string
	AWSRegion  string
	GossipAddr string // TCP listen address for the internal gossip server (e.g. ":9876")
}

func getConfig(ctx context.Context) (serverConfig, error) {
	cfg := serverConfig{
		Addr:       ":8080",
		Network:    "tcp",
		AWSRegion:  "us-east-1",
		GossipAddr: ":9876",
	}

	addr := flag.String("addr", cfg.Addr, "listen address")
	network := flag.String("network", cfg.Network, "listen network (tcp, tcp4, tcp6)")
	configS3 := flag.String("config-s3", "", "S3 URI for JSON instance config, e.g. s3://bucket/key")
	gossipAddr := flag.String("gossip-addr", cfg.GossipAddr, "TCP listen address for internal gossip server")
	flag.Parse()

	region, err := detectRegion(ctx)
	if err != nil {
		return serverConfig{}, err
	}
	cfg.AWSRegion = region

	if *configS3 != "" {
		if err := getS3Config(ctx, *configS3, cfg.AWSRegion, &cfg); err != nil {
			return serverConfig{}, fmt.Errorf("loading config from S3: %w", err)
		}
	}

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = *addr
		case "network":
			cfg.Network = *network
		case "gossip-addr":
			cfg.GossipAddr = *gossipAddr
		}
	})

	return cfg, nil
}

// setupPeerProvider builds an ec2PeerProvider if an ASG is configured.
// Returns nil (single-node mode) when no ASG is set.
func (cfg serverConfig) setupPeerProvider(ctx context.Context) (connect.PeerProvider, error) {
	if cfg.ASG == "" || cfg.GossipAddr == "" {
		return nil, nil
	}

	ip, err := getPublicIP()
	if err != nil {
		return nil, fmt.Errorf("getting public IP: %w", err)
	}
	if ip == nil {
		return nil, nil
	}

	scheme := "https"
	if cfg.Cert == "" {
		scheme = "http"
	}
	_, apiPort, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, err
	}
	proxyURL := buildIPURL(scheme, ip, apiPort)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		return nil, err
	}
	ec2Client := ec2svc.NewFromConfig(awsCfg, func(o *ec2svc.Options) {
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateEnabled
	})

	_, gossipPort, err := net.SplitHostPort(cfg.GossipAddr)
	if err != nil {
		return nil, err
	}

	pp := &ec2PeerProvider{
		proxyURL:     proxyURL,
		asgName:      cfg.ASG,
		region:       cfg.AWSRegion,
		selfIP:       ip,
		ec2:          ec2Client,
		gossipPort:   gossipPort,
		gossipScheme: scheme,
	}
	go pp.start(ctx)
	return pp, nil
}

// ec2PeerProvider implements connect.PeerProvider by polling EC2 for running
// instances in the same ASG.
type ec2PeerProvider struct {
	proxyURL     string
	asgName      string
	region       string
	selfIP       net.IP
	ec2          *ec2svc.Client
	gossipScheme string
	gossipPort   string

	mu    sync.RWMutex
	peers []string
}

func (p *ec2PeerProvider) Self() string { return p.proxyURL }

func (p *ec2PeerProvider) Peers() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.peers
}

func (p *ec2PeerProvider) refresh(ctx context.Context) {
	ips, err := getASGPeerIPs(ctx, p.region, p.asgName, p.selfIP)
	if err != nil {
		log.Printf("peer refresh: %v", err)
		return
	}
	peers := make([]string, 0, len(ips))
	for _, ip := range ips {
		peers = append(peers, buildIPURL(p.gossipScheme, ip, p.gossipPort))
	}

	p.mu.Lock()
	p.peers = peers
	p.mu.Unlock()
}

func (p *ec2PeerProvider) start(ctx context.Context) {
	p.refresh(ctx)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refresh(ctx)
		}
	}
}

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		for {
			log.Println("fatal:", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func run(ctx context.Context) error {
	cfg, err := getConfig(ctx)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	pp, err := cfg.setupPeerProvider(ctx)
	if err != nil {
		return err
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, cfg.Network, cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", cfg.Network, cfg.Addr, err)
	}

	var tlsCfg *tls.Config
	if cfg.Cert != "" {
		tlsCfg, err = buildTLS(cfg.Cert, cfg.Key)
		if err != nil {
			return fmt.Errorf("building TLS config: %w", err)
		}
		ln = tls.NewListener(ln, tlsCfg)
	}

	srvs := connect.NewServers(ctx, pp)

	if srvs.Gossip != nil {
		gossipLn, err := lc.Listen(ctx, "tcp", cfg.GossipAddr)
		if err != nil {
			return fmt.Errorf("gossip listen %s: %w", cfg.GossipAddr, err)
		}
		if tlsCfg != nil {
			gossipLn = tls.NewListener(gossipLn, tlsCfg)
		}
		go func() {
			if err := srvs.Gossip.Serve(gossipLn); err != nil && err != http.ErrServerClosed {
				log.Printf("gossip server: %v", err)
			}
		}()
	}

	return srvs.Public.Serve(ln)
}

func getS3Config(ctx context.Context, uri, region string, cfg *serverConfig) error {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
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

// getASGPeerIPs returns public IPv6 addresses of all running instances in the
// given ASG, excluding selfIP.
func getASGPeerIPs(ctx context.Context, region, asgName string, selfIP net.IP) ([]net.IP, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := ec2svc.NewFromConfig(awsCfg, func(o *ec2svc.Options) {
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateEnabled
	})
	out, err := client.DescribeInstances(ctx, &ec2svc.DescribeInstancesInput{
		Filters: []types.Filter{
			{Name: aws.String("tag:aws:autoscaling:groupName"), Values: []string{asgName}},
			{Name: aws.String("instance-state-name"), Values: []string{"running"}},
		},
	})
	if err != nil {
		return nil, err
	}
	var peers []net.IP
	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			ip, err := instanceIP(inst)
			if err != nil || ip == nil || ip.Equal(selfIP) {
				continue
			}
			peers = append(peers, ip)
		}
	}
	return peers, nil
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

// getPublicIP finds the first public IPv6 address on any up, non-loopback interface.
func getPublicIP() (net.IP, error) {
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
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			return ip, nil
		}
	}
	return nil, nil
}

// detectRegion returns the AWS region. Checks env vars first, then IMDS.
func detectRegion(ctx context.Context) (string, error) {
	for _, env := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if r := os.Getenv(env); r != "" {
			return r, nil
		}
	}
	out, err := imds.New(imds.Options{}).GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		return "", fmt.Errorf("querying IMDS for region: %w", err)
	}
	if out == nil {
		return "", fmt.Errorf("no region found")
	}
	return out.Region, nil
}

func buildIPURL(scheme string, ip net.IP, port string) string {
	if ip.To4() == nil {
		return fmt.Sprintf("%s://[%s]:%s", scheme, ip.String(), port)
	}

	return fmt.Sprintf("%s://%s:%s", scheme, ip.String(), port)
}
