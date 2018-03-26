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
	"crypto/rand"
)

type OPServer struct {
	OnionProxy *OnionProxy
}

// TODO: need global var to keep hopId for all instances of OP

type OnionProxy struct {
	addr string
	username string
	ircServerAddr string
	ORInfoByHopNum map[int]onion.OnionRouterInfo
	dirServer *rpc.Client
}

// Example Commands
// go run onion_proxy.go localhost:12345 127.0.0.1:7000 127.0.0.1:9000

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

	ORInfoByHopNum := make(map[int]onion.OnionRouterInfo)
	// Create OnionProxy instance
	onionProxy := &OnionProxy {
		addr: opAddr,
		dirServer: dirServer,
		ircServerAddr: ircServerAddr,
		ORInfoByHopNum: ORInfoByHopNum,
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

func (s *OPServer) Connect(username string, ack *bool) error {
	// Register username to OP
	s.OnionProxy.username = username
	fmt.Printf("Client username: %s \n", username)

	// First, wait to establish first new circuit
	s.OnionProxy.GetNewCircuit()
	//TODO: handle err

	// Then, start loop to establish new circuit every 2 mins
	//go s.OnionProxy.GetNewCircuitEveryTwoMinutes()
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

func (op OnionProxy) GetCircuitFromDServer() {
	var ORSet []onion.OnionRouterInfo //ORSet can be a struct containing the OR address and pubkey
	err := op.dirServer.Call("DServer.GetNodes", "", &ORSet)
	util.HandleFatalError("Could not get circuit from directory server", err)
	fmt.Printf("New circuit recieved from directory server: ")
	for hopNum, orInfo := range ORSet {
		op.ORInfoByHopNum[hopNum] = orInfo
		fmt.Printf("%v : %s", hopNum, orInfo.Address)
	}
	fmt.Printf("\n")
}

func (op OnionProxy) DialOR(ORAddr string) *rpc.Client {
	orServer, err := rpc.Dial("tcp", ORAddr)
	util.HandleFatalError("Could not dial onion router", err)
	return orServer
}

func (s *OPServer) SendMessage(message string, ack *bool) error {
	chatMessage := onion.ChatMessage {
		IRCServerAddr: s.OnionProxy.ircServerAddr,
		Username: s.OnionProxy.username,
		Message: message,
	}
	fmt.Printf("Recieved Message from Client for sending: %s \n", message)
	jsonData, _ := json.Marshal(&chatMessage)

	onion := s.OnionProxy.OnionizeData(onion.CHATMESSAGE, jsonData)
	err := s.OnionProxy.SendOnion(onion)
	*ack = true //TODO: change RPC response to chat history? error?
	return err
}

func (op OnionProxy) OnionizeData(dataType onion.DataType, coreData []byte) []byte {

	encryptedLayer := coreData
	fmt.Printf("Start onionizing data of type %v \n", dataType)
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

		pubKeyOfOR := op.ORInfoByHopNum[hopNum].PubKey
		encLayer, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pubKeyOfOR, jsonData, []byte(""))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		}
		encryptedLayer = encLayer
		fmt.Printf("Done onionizing data of type %v \n", dataType)
	}
	return encryptedLayer
}


func (op OnionProxy) SendOnion(onionToSend []byte) error {
	// Send onion to the guardNode via RPC
	cell := onion.Cell {
		// Can add more in cell if each layer needs more info other (such as hopId)
		Data: onionToSend,
	}
	fmt.Printf("Sending onion to guard node \n")
	var ack bool
	guardNodeRPCClient := op.DialOR(op.ORInfoByHopNum[0].Address)
	err := guardNodeRPCClient.Call("ORServer.DecryptCell", cell, &ack)
	util.HandleFatalError("Could not send onion to guard node", err)
	//TODO: handle error
	return err
}