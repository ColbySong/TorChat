package shared_structs

import (
	"crypto/rsa"
)


type Cell struct {
	CircId uint32
	Data []byte
}

type Onion struct {
	IsExitNode bool // true at layer of exit node
	NextAddress string // specifies the next address in the forward direction of the circuit
	Data []byte
}

type ChatMessage struct {
	IRCServerAddr string
	Username string
	Message string
}

type OnionRouterInfo struct {
	Address string
	PubKey  *rsa.PublicKey
}
