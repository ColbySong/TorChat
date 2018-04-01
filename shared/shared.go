package shared

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"
)

type Cell struct {
	CircuitId uint32
	Data      []byte
}

type Onion struct {
	IsExitNode  bool   // true at layer of exit node
	NextAddress string // specifies the next address in the forward direction of the circuit
	Data        []byte
}

type ChatMessage struct {
	IRCServerAddr string
	Username      string
	Message       string
}

type PollingMessage struct {
	IRCServerAddr string
	LastMessageId uint32
}

type OnionRouterInfos struct {
	PubKey  *ecdsa.PublicKey
	Hash    []byte
	SigS    *big.Int // signed with private key of directory server
	SigR    *big.Int // edsca.Sign returns R, S which is both needed to verify
	ORInfos []OnionRouterInfo
}

type OnionRouterInfo struct {
	Address string
	PubKey  *rsa.PublicKey
}

type CircuitInfo struct {
	CircuitId          uint32
	EncryptedSharedKey []byte
}
