package main

import (
	"encoding/gob"
	"net"
	"crypto/elliptic"
	"flag"
	"fmt"
	"os"
	"../util"

	"net/rpc"
	"encoding/json"
	"../onion"
	"time"
	"crypto/rsa"
	"crypto/sha256"
)

type OPServer struct {
	OnionProxy *OnionProxy
}

// TODO: need global var to keep hopId for all instances of OP

type OnionProxy struct {
	addr string
	username string
	ircServerAddr string
	ORInfoByHopNum map[int]onion.ORInfo
	dirServer *rpc.Client
	guardNodeServer *rpc.Client
}

// Example Commands
// go run onion_proxy.go localhost:12345 127.0.0.1:9000 127.0.0.1:8000
// go run onion_proxy.go localhost:12345 127.0.0.1:9000 127.0.0.1:8001

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{}) // TODO: this may be diff for rsa key?

	// Command line input parsing
	flag.Parse()
	if len(flag.Args()) != 3 {
		fmt.Fprintln(os.Stderr, "go run onion_proxy.go [dir-server ip:port] [irc-server ip:port] [op ip:port]")
		os.Exit(1)
	}

	dirServerAddr := flag.Arg(0)
	ircServerAddr := flag.Arg(1)
	opAddr := flag.Arg(2)

	// Establish RPC channel to server
	dirServer, err := rpc.Dial("tcp", dirServerAddr)
	util.HandleFatalError("Could not dial directory server", err)

	addr, err := net.ResolveTCPAddr("tcp", opAddr)
	util.HandleFatalError("Could not resolve onion_proxy address", err)

	inbound, err := net.ListenTCP("tcp", addr)
	util.HandleFatalError("Could not listen", err)

	fmt.Println("OP Address: ", opAddr)
	fmt.Println("Full Address: ", inbound.Addr().String())

	// Create OnionProxy instance
	onionProxy := &OnionProxy {
		addr: opAddr,
		dirServer: dirServer,
		ircServerAddr: ircServerAddr,
	}

	// Start listening for RPC calls from ORs
	opServer := new(OPServer)
	opServer.OnionProxy = onionProxy

	onionProxyServer := rpc.NewServer()
	onionProxyServer.Register(opServer)

	util.HandleFatalError("Listen error", err)
	util.OutLog.Printf("OPServer started. Receiving on %s\n", opAddr)


	// new OP connection for each incoming client
	for {
		conn, _ := inbound.Accept()
		go onionProxyServer.ServeConn(conn)
	}

}

func (s *OPServer) Connect(username string) error {
	// Register username to OP
	s.OnionProxy.username = username

	// First, wait to establish first new circuit
	s.OnionProxy.GetNewCircuit()
	//TODO: handle err

	// Then, start loop to establish new circuit every 2 mins
	go s.OnionProxy.GetNewCircuitEveryTwoMinutes()
	return nil
}

func (op OnionProxy) GetNewCircuit() error {
	op.GetCircuitFromDServer()
	return nil
}

func (op OnionProxy) GetNewCircuitEveryTwoMinutes() error {
	for {
		select {
		case <- time.After(120 * time.Second): //get new circuit after 2 minutes
			op.GetCircuitFromDServer()
		}
	}
}

func (op OnionProxy) GetCircuitFromDServer() []onion.ORInfo {
	//TODO: Wait for change for Colby to get back addr/pubkey from GetNodes to DServer; []ORInfo is a suggestion
	var ORSet []onion.ORInfo //ORSet can be a struct containing the OR address and pubkey
	op.dirServer.Call("DServer.GetNodes", nil, &ORSet)
	for hopNum, orInfo := range ORSet {
		op.ORInfoByHopNum[hopNum] = orInfo
	}

	// Initiate and save RPC connection with guard node
	op.DialOR(op.ORInfoByHopNum[0].Address)
	return ORSet
}

func (op OnionProxy) DialOR(ORAddr string) error {
	orServer, err := rpc.Dial("tcp", ORAddr)
	util.HandleFatalError("Could not dial onion router", err)
	op.guardNodeServer = orServer
	return nil
}

func (s *OPServer) SendMessage(message string, chatHistory *string) error {

	chatMessage := onion.ChatMessage {
		IRCServerAddr: s.OnionProxy.ircServerAddr,
		Username: s.OnionProxy.username,
		Message: message,
	}
	jsonData, _ := json.Marshal(&chatMessage)

	onion := s.OnionProxy.OnionizeData(onion.CHATMESSAGE, jsonData)
	err := s.OnionProxy.SendOnion(onion)
	return err
}

func (op OnionProxy) OnionizeData(dataType onion.DataType, coreData []byte) []byte {

	encryptedLayer := coreData

	for hopNum := len(op.ORInfoByHopNum); hopNum < 0; hopNum-- {
		unencryptedLayer := onion.Onion{
			DataType: dataType,
			Data: encryptedLayer,
			NextAddress: op.ORInfoByHopNum[hopNum].Address,
		}

		if hopNum == len(op.ORInfoByHopNum){
			unencryptedLayer.IsExitNode = true
		}

		jsonData, _ := json.Marshal(&unencryptedLayer)

		pubKeyOfOR := op.ORInfoByHopNum[hopNum].Pubkey
		encryptedLayer, _ = rsa.EncryptOAEP(sha256.New(), nil, pubKeyOfOR, jsonData, nil)
	}
	return encryptedLayer
}


func (op OnionProxy) SendOnion(onion []byte) error {
	// Send onion to the guardNode via RPC
	cell := onion.Cell {
		// Can add more in cell if each layer needs more info other (such as hopId)
		Data: onion,
	}
	var ack bool
	err := op.guardNodeServer.Call("ORServer.DecryptCell", cell, &ack)
	//TODO: handle error
	return err
}