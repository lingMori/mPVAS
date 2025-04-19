package p2p

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

type P2PHost struct {
	Host       host.Host
	listenPort int
	privKey    crypto.PrivateKey // 当然我们没必要用key，留一个备份罢了，通信部分完全可以不用privKey
	ctx        context.Context
}

func NewHost(ctx context.Context, listenPort int, privKey crypto.PrivateKey) (*P2PHost, error) {

	// load config from input

	h, err := libp2p.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create p2p host: %w", err)
	}

	return &P2PHost{
		Host:       h,
		listenPort: listenPort,
		privKey:    privKey,
		ctx:        ctx,
	}, nil
}

func (p *P2PHost) GetID() peer.ID {
	return p.Host.ID()
}

func (p *P2PHost) Close() error {
	return p.Host.Close()
}

func (p *P2PHost) Connect(peerInfo peer.AddrInfo) error {
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()

	return p.Host.Connect(ctx, peerInfo)
}
