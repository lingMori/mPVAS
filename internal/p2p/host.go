package p2p

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/multiformats/go-multiaddr"
)

// P2PHost 封装了libp2p的host和相关功能
type P2PHost struct {
	Host       host.Host
	listenPort int
	privKey    crypto.PrivKey
	ctx        context.Context
}

// NewHost 创建一个新的p2p host
func NewHost(ctx context.Context, listenPort int, privKey crypto.PrivKey) (*P2PHost, error) {
	// 如果没有提供私钥，则生成一个
	var err error
	if privKey == nil {
		privKey, _, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	// 构造监听地址
	addr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort))
	if err != nil {
		return nil, fmt.Errorf("failed to create multiaddr: %w", err)
	}

	// 创建libp2p host
	h, err := libp2p.New(
		libp2p.ListenAddrs(addr),
		libp2p.Identity(privKey),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.NATPortMap(), // 启用NAT端口映射
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	return &P2PHost{
		Host:       h,
		listenPort: listenPort,
		privKey:    privKey,
		ctx:        ctx,
	}, nil
}

// GetID 获取host的PeerID
func (p *P2PHost) GetID() peer.ID {
	return p.Host.ID()
}

// GetMultiaddrs 获取host的监听地址
func (p *P2PHost) GetMultiaddrs() []multiaddr.Multiaddr {
	return p.Host.Addrs()
}

// Connect 连接到指定的peer
func (p *P2PHost) Connect(peerInfo peer.AddrInfo) error {
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()

	return p.Host.Connect(ctx, peerInfo)
}

// Close 关闭p2p host
func (p *P2PHost) Close() error {
	return p.Host.Close()
}
