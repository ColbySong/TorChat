package onion

import (
	"crypto/ecdsa"
)

type DataType int

const (
	CONNECT DataType = iota
	CHATMESSAGE
	TEARDOWN
)

type Cell struct {
	FromAddr string
	FromHopId int
	Data []byte

}

type Onion struct {
	DataType DataType //ChatMessage or Teardown to know how to jsonUnmarshalData
	IsExitNode bool // true at layer of exit node
	NextAddress string // specifies the next address in the forward direction of the circuit
	Data []byte
	// data for each DataType:
	// CREATE: next node address,  BEGIN: IRC server address, DATA: chat message
}

type ChatMessage struct {
	IRCServerAddr string
	Username string
	Message string
}

type ORInfo struct {
	Address string
	Pubkey *ecdsa.PublicKey
}
