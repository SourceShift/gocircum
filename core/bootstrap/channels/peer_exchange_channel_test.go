package channels

import (
	"testing"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/stretchr/testify/assert"
)

func TestPeerExchangeChannelWithSecureResolver(t *testing.T) {
	// Create mock resolver
	mockResolver := new(MockSecureResolver)

	// Create channel options with the resolver and valid endpoint formats (with port numbers)
	opts := PeerExchangeOptions{
		InitialPeers:    []string{"peer1.example.com:443", "peer2.example.com:8080"},
		Timeout:         15 * time.Second,
		Priority:        10,
		RefreshInterval: 20 * time.Minute,
		MaxPeers:        50,
		Resolver:        mockResolver,
	}

	// Create channel with the secure resolver
	logger := logging.GetLogger()
	channel := NewPeerExchangeChannel(opts, logger)

	// Verify channel configuration
	assert.NotNil(t, channel)
	assert.Equal(t, "peer_exchange", channel.Name())
	assert.Equal(t, 15*time.Second, channel.Timeout())
	assert.Equal(t, 10, channel.Priority())
	assert.NotNil(t, channel.client)

	// Verify peer cache initialization
	assert.Len(t, channel.peerCache, 2)
	_, hasPeer1 := channel.peerCache["peer1.example.com:443"]
	_, hasPeer2 := channel.peerCache["peer2.example.com:8080"]
	assert.True(t, hasPeer1, "Peer cache should contain peer1.example.com:443")
	assert.True(t, hasPeer2, "Peer cache should contain peer2.example.com:8080")
}

func TestPeerExchangeChannelWithoutResolver(t *testing.T) {
	// Create channel options without a resolver and with valid endpoint formats
	opts := PeerExchangeOptions{
		InitialPeers:    []string{"peer3.example.com:443", "peer4.example.com:8080"},
		Timeout:         25 * time.Second,
		Priority:        5,
		RefreshInterval: 10 * time.Minute,
		MaxPeers:        30,
		// No resolver
	}

	// Create channel without a secure resolver
	logger := logging.GetLogger()
	channel := NewPeerExchangeChannel(opts, logger)

	// Verify channel configuration
	assert.NotNil(t, channel)
	assert.Equal(t, "peer_exchange", channel.Name())
	assert.Equal(t, 25*time.Second, channel.Timeout())
	assert.Equal(t, 5, channel.Priority())
	assert.NotNil(t, channel.client)

	// Verify peer cache initialization
	assert.Len(t, channel.peerCache, 2)
	_, hasPeer3 := channel.peerCache["peer3.example.com:443"]
	_, hasPeer4 := channel.peerCache["peer4.example.com:8080"]
	assert.True(t, hasPeer3, "Peer cache should contain peer3.example.com:443")
	assert.True(t, hasPeer4, "Peer cache should contain peer4.example.com:8080")
}
