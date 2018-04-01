package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
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
const RSAKeySize = 2048

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
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
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

	if err = onionRouter.registerNode(); err != nil {
		util.HandleFatalError("Could not register onion router with directory server", err)
	}

	go onionRouter.startSendingHeartbeatsToServer()

	// Start listening for RPC calls from other onion routers
	orServer := new(ORServer)
	orServer.OnionRouter = onionRouter

	onionRouterServer := rpc.NewServer()
	onionRouterServer.Register(orServer)

	util.OutLog.Printf("ORServer started. Receiving on %s\n", orAddr)

	for {
		conn, _ := inbound.Accept()
		go onionRouterServer.ServeConn(conn)
	}
}

// Registers the onion router on the directory server by making an RPC call.
func (or OnionRouter) registerNode() error {
	if _, err := net.ResolveTCPAddr("tcp", or.addr); err != nil {
		return err
	}

	req := OnionRouterInfo{
		Address: or.addr,
		PubKey:  or.pubKey,
	}

	var resp bool // there is no response for this RPC call
	if err := or.dirServer.Call("DServer.RegisterNode", req, &resp); err != nil {
		return err
	}

	return nil
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
	var chatMessage shared.ChatMessage
	if err := json.Unmarshal(chatMessageByteArray, &chatMessage); err != nil {
		return err
	}

	ircServer, err := rpc.Dial("tcp", chatMessage.IRCServerAddr)
	if err != nil {
		return err
	}

	message := chatMessage.Username + ": " + chatMessage.Message

	var ack bool
	if err = ircServer.Call("CServer.PublishMessage", message, &ack); err != nil {
		util.HandleNonFatalError("Could not publish message to IRC server", err)
		return err
	}
	ircServer.Close()

	util.OutLog.Printf("Deliver chat message to IRC server: %s\n", message)

	return nil
}

func (or OnionRouter) RelayChatMessageOnion(nextORAddress string, nextOnion []byte, circuitId uint32) error {
	util.OutLog.Printf("\nRelay chat message:\n    Circuit ID: %v\n    Next OR: %s\n", circuitId, nextORAddress)
	cell := shared.Cell{
		CircuitId: circuitId,
		Data:      nextOnion,
	}

	nextORServer, err := DialOR(nextORAddress)
	if err != nil {
		return err
	}

	var ack bool
	if err := nextORServer.Call("ORServer.DecryptChatMessageCell", cell, &ack); err != nil {
		return err
	}
	nextORServer.Close()

	return nil
}

func DialOR(ORAddr string) (*rpc.Client, error) {
	orServer, err := rpc.Dial("tcp", ORAddr)
	if err != nil {
		util.HandleNonFatalError("Could not dial onion router: "+ORAddr, err)
		return nil, err
	}
	return orServer, nil
}

func (s *ORServer) DecryptChatMessageCell(cell shared.Cell, ack *bool) error {
	util.OutLog.Println("Recieved chat message cell, decrypting...")
	key := sharedKeysByCircuitId[cell.CircuitId]
	cipherkey, err := aes.NewCipher(key)
	if err != nil {
		util.HandleNonFatalError("Could not create cipher key", err)
		return err
	}

	prefix := cell.Data[:aes.BlockSize]
	jsonData := cell.Data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(cipherkey, prefix)
	cfb.XORKeyStream(jsonData, jsonData)

	var currOnion shared.Onion
	if err = json.Unmarshal(jsonData, &currOnion); err != nil {
		util.HandleNonFatalError("Could not unmarshal onion", err)
	}
	nextOnion := currOnion.Data

	if currOnion.IsExitNode {
		if err = s.OnionRouter.DeliverChatMessage(currOnion.Data); err != nil {
			util.HandleNonFatalError("Could not deliver chat message", err)
		}
	} else {
		if err = s.OnionRouter.RelayChatMessageOnion(currOnion.NextAddress, nextOnion, cell.CircuitId); err != nil {
			util.HandleNonFatalError("Could not relay chat message", err)
		}
	}

	*ack = true
	return nil
}

func (s *ORServer) DecryptPollingCell(cell shared.Cell, resp *[]string) error {
	key := sharedKeysByCircuitId[cell.CircuitId]
	cipherkey, err := aes.NewCipher(key)
	if err != nil {
		util.HandleNonFatalError("Could not create cipher key", err)
		return err
	}

	prefix := cell.Data[:aes.BlockSize]
	jsonData := cell.Data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(cipherkey, prefix)
	cfb.XORKeyStream(jsonData, jsonData)

	var currOnion shared.Onion
	err = json.Unmarshal(jsonData, &currOnion)
	if err != nil {
		util.HandleNonFatalError("Could not unmarshal onion", err)
		return err
	}
	nextOnion := currOnion.Data

	var messages []string
	if currOnion.IsExitNode {
		messages, err = s.OnionRouter.DeliverPollingMessage(currOnion.Data)
		if err != nil {
			util.HandleNonFatalError("Could not retrieve new messages from IRC server", err)
			return err
		}
	} else {
		messages, err = s.OnionRouter.RelayPollingOnion(currOnion.NextAddress, nextOnion, cell.CircuitId)
		if err != nil {
			util.HandleNonFatalError("Could not relay polling message to next OR: "+currOnion.NextAddress, err)
			return err
		}
	}

	*resp = messages
	return nil
}

func (or OnionRouter) DeliverPollingMessage(pollingMessageByteArray []byte) ([]string, error) {
	var pollingMessage shared.PollingMessage
	if err := json.Unmarshal(pollingMessageByteArray, &pollingMessage); err != nil {
		return nil, err
	}

	ircServer, err := rpc.Dial("tcp", pollingMessage.IRCServerAddr)
	if err != nil {
		return nil, err
	}

	var messages []string
	if err = ircServer.Call("CServer.GetNewMessages", pollingMessage.LastMessageId, &messages); err != nil {
		util.HandleNonFatalError("Could not retrieve new messages from IRC server", err)
		return nil, err
	}
	ircServer.Close()

	return messages, nil
}

func (or OnionRouter) RelayPollingOnion(nextORAddress string, nextOnion []byte, circuitId uint32) ([]string, error) {
	cell := shared.Cell{
		CircuitId: circuitId,
		Data:      nextOnion,
	}

	nextORServer, err := DialOR(nextORAddress)
	if err != nil {
		return nil, err
	}

	var resp []string
	if err := nextORServer.Call("ORServer.DecryptPollingCell", cell, &resp); err != nil {
		return nil, err
	}
	nextORServer.Close()

	return resp, nil
}

func (s *ORServer) SendCircuitInfo(circuitInfo shared.CircuitInfo, ack *bool) error {
	sharedKey, err := util.RSADecrypt(s.OnionRouter.privKey, circuitInfo.EncryptedSharedKey)
	if err != nil {
		util.HandleNonFatalError("Could not decrypt shared key", err)
	}
	sharedKeysByCircuitId[circuitInfo.CircuitId] = sharedKey

	util.OutLog.Printf("\nReceived circuit info:\n    Circuit ID %v\n    Shared Key: %s\n", circuitInfo.CircuitId, hex.EncodeToString(sharedKey))

	*ack = true
	return nil
}
