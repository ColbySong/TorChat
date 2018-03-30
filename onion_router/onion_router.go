package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"flag"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/json"

	"../shared"
	"../util"
)

const HeartbeatMultiplier = 2

type OnionRouter struct {
	addr      string
	dirServer *rpc.Client
	pubKey    *rsa.PublicKey
	privKey   *rsa.PrivateKey
}

type OnionRouterInfo struct {
	Address string
	PubKey  *rsa.PublicKey
}

var sharedKeysByCircuitId = make(map[uint32][]byte)

// Start the onion router.
// go run onion_router.go localhost:12345 127.0.0.1:8000
func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	// Command line input parsing
	flag.Parse()
	if len(flag.Args()) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run onion_router.go [dir-server ip:port] [or ip:port]")
		os.Exit(1)
	}

	dirServerAddr := flag.Arg(0)
	orAddr := flag.Arg(1)

	// Generate RSA PublicKey and PrivateKey
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	util.HandleFatalError("Could not generate RSA key", err)
	pub := &priv.PublicKey

	// Establish RPC channel to server
	dirServer, err := rpc.Dial("tcp", dirServerAddr)
	util.HandleFatalError("Could not dial directory server", err)

	addr, err := net.ResolveTCPAddr("tcp", orAddr)
	util.HandleFatalError("Could not resolve onion-router address", err)

	inbound, err := net.ListenTCP("tcp", addr)
	util.HandleFatalError("Could not listen", err)

	util.OutLog.Println("OR Address: ", orAddr)
	util.OutLog.Println("Full Address: ", inbound.Addr().String())

	// Create OnionRouter instance
	onionRouter := &OnionRouter{
		addr:      orAddr,
		dirServer: dirServer,
		pubKey:    pub,
		privKey:   priv,
	}

	onionRouter.registerNode()

	go onionRouter.startSendingHeartbeatsToServer()

	// Start listening for RPC calls from other onion routers
	orServer := new(ORServer)
	orServer.OnionRouter = onionRouter

	onionRouterServer := rpc.NewServer()
	onionRouterServer.Register(orServer)

	util.HandleFatalError("Listen error", err)
	util.OutLog.Printf("ORServer started. Receiving on %s\n", orAddr)

	for {
		conn, _ := inbound.Accept()
		go onionRouterServer.ServeConn(conn)
	}
}

// Registers the onion router on the directory server by making an RPC call.
func (or OnionRouter) registerNode() {
	_, err := net.ResolveTCPAddr("tcp", or.addr)
	util.HandleFatalError("Could not resolve tcp addr", err)
	req := OnionRouterInfo{
		Address: or.addr,
		PubKey:  or.pubKey,
	}
	var resp bool // there is no response for this RPC call
	err = or.dirServer.Call("DServer.RegisterNode", req, &resp)
	util.HandleFatalError("Could not register onion router", err)
}

// Periodically send heartbeats to the server at period defined by server times a frequency multiplier
func (or OnionRouter) startSendingHeartbeatsToServer() {
	for {
		or.sendHeartBeat()
		time.Sleep(time.Duration(1000) / HeartbeatMultiplier * time.Millisecond)
	}
}

// Send a single heartbeat to the server
func (or OnionRouter) sendHeartBeat() {
	var ignoredResp bool // there is no response for this RPC call
	err := or.dirServer.Call("DServer.KeepNodeOnline", or.addr, &ignoredResp)
	util.HandleFatalError("Could not send heartbeat to directory server", err)
}

func (or OnionRouter) markNodeOffline(pubKey *ecdsa.PublicKey) {
	var ignoredResp bool // there is no response for this RPC call
	err := or.dirServer.Call("DServer.MarkNodeOffline", *or.pubKey, &ignoredResp)
	util.HandleNonFatalError("Could not mark node offline", err)
}

func (or OnionRouter) registerUser(userName string) {
	var ignoredResp bool // there is no response for this RPC call
	err := or.dirServer.Call("IRCServer.RegisterUserName", userName, &ignoredResp)
	util.HandleNonFatalError("Could not register user with IRC", err)
}

func (or OnionRouter) publishMessage(userName string, msg string) {
	var ignoredResp bool // there is no response for this RPC call
	err := or.dirServer.Call("IRCServer.PublishMessage", userName+msg, &ignoredResp)
	util.HandleNonFatalError("Could not publish message to IRC", err)
}

type ORServer struct {
	OnionRouter *OnionRouter
}

func (or OnionRouter) DeliverChatMessage(chatMessageByteArray []byte) error {
	// TODO: send username/msg to IRC server
	var chatMessage shared.ChatMessage
	err := json.Unmarshal(chatMessageByteArray, &chatMessage)
	util.HandleFatalError("Could not unmarshal chat message", err)

	ircServer, err := rpc.Dial("tcp", chatMessage.IRCServerAddr)
	util.HandleFatalError("Could not dial IRC server", err)

	var ack bool
	err = ircServer.Call("CServer.PublishMessage", chatMessage.Username+": "+chatMessage.Message, &ack)
	ircServer.Close()
	util.HandleFatalError("Could not send message to IRC server", err)

	return nil
}

func (or OnionRouter) RelayChatMessageOnion(nextORAddress string, nextOnion []byte, circuitId uint32) error {
	util.OutLog.Printf("Relaying chat message to next OR: %s with circuit id: %v\n", nextORAddress, circuitId)
	cell := shared.Cell{
		CircuitId: circuitId,
		Data:      nextOnion,
	}

	nextORServer := DialOR(nextORAddress)
	var ack bool
	err := nextORServer.Call("ORServer.DecryptChatMessageCell", cell, &ack)
	nextORServer.Close()
	return err
}

func DialOR(ORAddr string) *rpc.Client {
	orServer, err := rpc.Dial("tcp", ORAddr)
	util.HandleFatalError("Could not dial OR", err)
	return orServer
}

func (s *ORServer) DecryptChatMessageCell(cell shared.Cell, ack *bool) error {
	key := sharedKeysByCircuitId[cell.CircuitId]
	cipherkey, err := aes.NewCipher(key)
	util.HandleFatalError("Could not create cipher key", err)

	prefix := cell.Data[:aes.BlockSize]
	jsonData := cell.Data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(cipherkey, prefix)
	cfb.XORKeyStream(jsonData, jsonData)

	var currOnion shared.Onion
	err = json.Unmarshal(jsonData, &currOnion)
	util.HandleFatalError("Could not unmarshal onion", err)
	nextOnion := currOnion.Data

	if currOnion.IsExitNode {
		err = s.OnionRouter.DeliverChatMessage(currOnion.Data)
		util.HandleFatalError("Could not deliver chat message", err)
		util.OutLog.Println("Deliver chat message to IRC server")
	} else {
		err = s.OnionRouter.RelayChatMessageOnion(currOnion.NextAddress, nextOnion, cell.CircuitId)
		util.HandleFatalError("Could not relay chat message", err)
		util.OutLog.Printf("Relay chat message onion to next addr: %s\n", currOnion.NextAddress)
	}

	*ack = true
	return nil
}

func (s *ORServer) DecryptPollingCell(cell shared.Cell, ack *[]string) error {
	key := sharedKeysByCircuitId[cell.CircuitId]
	cipherkey, err := aes.NewCipher(key)
	util.HandleFatalError("Could not create cipher key", err)

	prefix := cell.Data[:aes.BlockSize]
	jsonData := cell.Data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(cipherkey, prefix)
	cfb.XORKeyStream(jsonData, jsonData)

	var currOnion shared.Onion
	err = json.Unmarshal(jsonData, &currOnion)
	util.HandleFatalError("Could not unmarshal onion", err)
	nextOnion := currOnion.Data

	var messages []string
	if currOnion.IsExitNode {
		messages, err = s.OnionRouter.DeliverPollingMessage(currOnion.Data)
		util.HandleFatalError("Could not deliver polling message", err)
		// fmt.Printf("Deliver polling message to IRC server")
	} else {
		messages, err = s.OnionRouter.RelayPollingOnion(currOnion.NextAddress, nextOnion, cell.CircuitId)
		util.HandleFatalError("Could not relay polling message", err)
		// fmt.Printf("Send polling message onion to next addr: %s \n", currOnion.NextAddress)
	}

	*ack = messages
	return nil
}

func (or OnionRouter) DeliverPollingMessage(pollingMessageByteArray []byte) ([]string, error) {
	var pollingMessage shared.PollingMessage
	json.Unmarshal(pollingMessageByteArray, &pollingMessage)

	ircServer, err := rpc.Dial("tcp", pollingMessage.IRCServerAddr)
	var messages []string
	err = ircServer.Call("CServer.GetNewMessages", pollingMessage.LastMessageId, &messages)
	ircServer.Close()
	util.HandleFatalError("Could not dial IRC", err)

	return messages, nil
}

func (or OnionRouter) RelayPollingOnion(nextORAddress string, nextOnion []byte, circuitId uint32) ([]string, error) {
	// util.OutLog.Printf("Relaying chat message to next OR: %s with circuit id: %v\n", nextORAddress, circuitId)
	cell := shared.Cell{
		CircuitId: circuitId,
		Data:      nextOnion,
	}

	nextORServer := DialOR(nextORAddress)
	var resp []string
	err := nextORServer.Call("ORServer.DecryptPollingCell", cell, &resp)
	nextORServer.Close()
	util.HandleFatalError("Could not decrypt polling cell", err)

	return resp, err
}

func (s *ORServer) SendCircuitInfo(circuitInfo shared.CircuitInfo, ack *bool) error {
	sharedKey := util.RSADecrypt(s.OnionRouter.privKey, circuitInfo.EncryptedSharedKey)
	sharedKeysByCircuitId[circuitInfo.CircuitId] = sharedKey

	util.OutLog.Printf("Received circuit info: CircuitId %v, Shared Key: %s\n", circuitInfo.CircuitId, sharedKey)

	*ack = true
	return nil
}
