package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"strings"
	"time"

	"io/ioutil"
	"net/http"

	"../util"
	"crypto/sha256"
	"../onion"
	"crypto/rsa"
	"encoding/json"
)

const HeartbeatMultiplier = 2

type OnionRouter struct {
	addr      string
	dirServer *rpc.Client
	pubKey    *ecdsa.PublicKey
	privKey   *ecdsa.PrivateKey
}

type OnionRouterInfo struct {
	Address string
	PubKey  ecdsa.PublicKey
}

// Example Commands
// go run onion_router.go localhost:12345 127.0.0.1:8000 3081a40201010430c9c10ec4a18f63f86fb4d319862ee2214bef9bca567cae982fa5a412c2b32856de7a36546f75e128202f0d2f610351faa00706052b81040022a1640362000485a0d603cffce115a17bbe2edddb198d0f3fe3ad426123a5df2fd3d442acdd790dcb3c544f34f7793b2e0ecd9a82db3b8acf9de997ac7e578ded48108bf829cf08e76902eb6abbbd3cf10208f4afcbbb531199f73949377ad1cfe84a3899bfd0
// go run onion_router.go localhost:12345 127.0.0.1:8001 3081a40201010430aeb7b244cf5ee8a952ff378a140275a0d7f98a7c44faca12357867c667b860fa2aaf7bf9039d3b481479bf0fd512097fa00706052b81040022a1640362000449e30da789d5b12a9487a96d70d69b6b8cbd6821d7a647f35c18a8d5f0969054ae3130e7a2a813363eb578747bc77048b700badea328df20ce68a58fcd0e4166f538f9393e0b4072d069cc4cc631271660dc5ebebb20531f11eeb4bd5aa6a5ca

// Start the onion router.
func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	// Command line input parsing
	flag.Parse()
	if len(flag.Args()) != 3 {
		fmt.Fprintln(os.Stderr, "go run onion-router.go [dir-server ip:port] [or ip:port] [privKey]")
		os.Exit(1)
	}

	dirServerAddr := flag.Arg(0)
	orAddr := flag.Arg(1)
	privKey := flag.Arg(2) // Don't need public key: follow @367 on piazza

	// Decode keys from strings
	privKeyBytesRestored, _ := hex.DecodeString(privKey)
	priv, err := x509.ParseECPrivateKey(privKeyBytesRestored)
	util.HandleFatalError("Couldn't parse private key", err)
	pub := priv.PublicKey

	// Establish RPC channel to server
	dirServer, err := rpc.Dial("tcp", dirServerAddr)
	util.HandleFatalError("Could not dial directory server", err)

	addr, err := net.ResolveTCPAddr("tcp", orAddr)
	util.HandleFatalError("Could not resolve onion-router address", err)

	inbound, err := net.ListenTCP("tcp", addr)
	util.HandleFatalError("Could not listen", err)

	// strings := strings.Split(inbound.Addr().String(), ":")
	// port := strings[len(strings)-1]
	// myIP := getMyIP()
	// fullAddress := myIP + ":" + port

	//_, rerr := net.ResolveTCPAddr("tcp", fullAddress)
	//fmt.Println(rerr)

	fmt.Println("OR Address: ", orAddr)
	fmt.Println("Full Address: ", inbound.Addr().String())
	// Create OnionRouter instance
	onionRouter := &OnionRouter{
		addr:      orAddr,
		dirServer: dirServer,
		pubKey:    &pub,
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

	// saveAddrAndPrivKeyToFile(orAddr, privKey)

	for {
		conn, _ := inbound.Accept()
		go onionRouterServer.ServeConn(conn)
	}
}

// Registers the onion router on the directory server by making an RPC call.
func (or OnionRouter) registerNode() {
	fmt.Println("REGISTER NODE")
	_, err := net.ResolveTCPAddr("tcp", or.addr)
	util.HandleFatalError("Could not resolve tcp addr", err)
	req := OnionRouterInfo{
		Address: or.addr,
		PubKey:  *or.pubKey,
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
	fmt.Println("SEND HEART BEAT")
	var ignoredResp bool // there is no response for this RPC call
	err := or.dirServer.Call("DServer.KeepNodeOnline", *or.pubKey, &ignoredResp)
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

func getMyIP() string {
	resp, _ := http.Get("http://myexternalip.com/raw")
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	defer resp.Body.Close()
	bodyString = strings.TrimSuffix(bodyString, "\n")

	return bodyString
}

func saveAddrAndPrivKeyToFile(addr string, privKey string) {
	d1 := []byte(addr)
	f1, err := os.Create("minerAddr")
	util.HandleFatalError("Couldn't create address file", err)
	_, err = f1.Write(d1)
	util.HandleFatalError("Couldn't save address to file", err)
	f1.Close()

	d2 := []byte(privKey)
	f2, err := os.Create("minerPrivKey")
	util.HandleFatalError("Couldn't create privKey file", err)
	_, err = f2.Write(d2)
	util.HandleFatalError("Couldn't save privKey to file", err)
	f2.Close()

	util.OutLog.Println("Saved miner address and private key to files.")
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
	err = ircServer.Call("IRCServer.SendChatMessage",
		chatMessage.Username + ":" + chatMessage.Message, &ack)
	// TODO: send struct to IRC for msg
	util.HandleFatalError("Could not dial IRC", err)
	return nil
}

func (or OnionRouter) relayOnion(nextORAddress string, nextOnion []byte) error{
	cell := onion.Cell{
		Data: nextOnion,
	}

	nextORServer := DialOR(nextORAddress)
	var ack bool
	err := nextORServer.Call("ORServer.DecryptCell", cell, &ack)
	return err
}

func DialOR(ORAddr string) *rpc.Client{
	orServer, err := rpc.Dial("tcp", ORAddr)
	util.HandleFatalError("Could not dial OR", err)
	return orServer
}

func (s *ORServer) DecryptCell(cell onion.Cell, ack bool) error {

	// decrypt incoming cell Data field
	unencryptedOnion, _ := rsa.DecryptOAEP(sha256.New(), nil, s.OnionRouter.privKey, cell.Data, nil)

	var currOnion onion.Onion
	json.Unmarshal(unencryptedOnion, &currOnion)

	nextOnion := currOnion.Data

	// read first ___# of bytes to see if create, begin, data
	switch currOnion.DataType {
	case onion.CHATMESSAGE:
		if currOnion.IsExitNode {
			s.OnionRouter.DeliverChatMessage(currOnion.Data)
		} else {
			s.OnionRouter.relayOnion(currOnion.NextAddress, nextOnion)
		}

	case onion.TEARDOWN:
	}

	//TODO: handle err
	ack = true
	return nil
}
