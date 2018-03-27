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

	"../onion"
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
	priv, err := rsa.GenerateKey(rand.Reader, 2048) //2048
	util.HandleFatalError("Could not generate RSA key", err)
	pub := &priv.PublicKey

	/* Sample code to encrypt/decrypt message

	message := []byte("Plain text message!")
	label := []byte("")
	hash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, message, label)
	util.HandleFatalError("Could not encrypt message", err)
	util.OutLog.Printf("OAEP encrypted [%s] to \n[%x]\n", string(message), ciphertext)

	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, label)
	util.HandleFatalError("Could not decrypt message", err)
	util.OutLog.Printf("OAEP decrypted [%x] to \n[%s]\n", ciphertext, plainText)

	*/

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
	var chatMessage onion.ChatMessage
	json.Unmarshal(chatMessageByteArray, &chatMessage)

	ircServer, err := rpc.Dial("tcp", chatMessage.IRCServerAddr)
	var ack bool
	err = ircServer.Call("CServer.PublishMessage",
		chatMessage.Username+":"+chatMessage.Message, &ack)
	// TODO: send struct to IRC for msg
	util.HandleFatalError("Could not dial IRC", err)
	return nil
}

func (or OnionRouter) RelayChatMessageOnion(nextORAddress string, nextOnion []byte) error {
	cell := onion.Cell{
		Data: nextOnion,
	}

	nextORServer := DialOR(nextORAddress)
	var ack bool
	err := nextORServer.Call("ORServer.DecryptChatMessageCell", cell, &ack)
	return err
}

func DialOR(ORAddr string) *rpc.Client {
	orServer, err := rpc.Dial("tcp", ORAddr)
	util.HandleFatalError("Could not dial OR", err)
	return orServer
}

func (s *ORServer) DecryptChatMessageCell(cell onion.Cell, ack *bool) error {
	fmt.Printf("Recieved Onion \n")

	//TODO: create symmetric shared key with OP
	//TODO: read cell.CircId to identify which shared key to use
	key := []byte("0123456789123456") // should be multiple of 16 bytes
	cipherkey, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from cipher creation: %s\n", err)
	}

	iv := cell.Data[:aes.BlockSize]
	jsonData := cell.Data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(cipherkey, iv)
	cfb.XORKeyStream(jsonData, jsonData)

	var currOnion onion.Onion
	json.Unmarshal(jsonData, &currOnion)
	nextOnion := currOnion.Data

	if currOnion.IsExitNode {
		s.OnionRouter.DeliverChatMessage(currOnion.Data)
		fmt.Printf("Deliver chat message to IRC server")
	} else {
		s.OnionRouter.RelayChatMessageOnion(currOnion.NextAddress, nextOnion)
		fmt.Printf("Send chat message onion to next addr: %s \n", currOnion.NextAddress)
	}

	//TODO: handle err
	*ack = true
	return nil
}
