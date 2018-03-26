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
	"../shared_structs"
	"time"
	"crypto/aes"
	"io"
	"crypto/rand"
	"crypto/cipher"
)

type OPServer struct {
	OnionProxy *OnionProxy
}

type OnionProxy struct {
	addr string
	username string
	circId uint32
	ircServerAddr string
	ORInfoByHopNum map[int]shared_structs.OnionRouterInfo
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

	ORInfoByHopNum := make(map[int]shared_structs.OnionRouterInfo)
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

func (op OnionProxy) GetCircuitFromDServer() {
	op.circId = 0 //TODO: generate random uint32 for circId
	var ORSet []shared_structs.OnionRouterInfo //ORSet can be a struct containing the OR address and pubkey
	err := op.dirServer.Call("DServer.GetNodes", "", &ORSet)
	util.HandleFatalError("Could not get circuit from directory server", err)
	fmt.Printf("New circuit recieved from directory server: ")
	for hopNum, orInfo := range ORSet {
		op.ORInfoByHopNum[hopNum] = orInfo
		fmt.Printf(" hopnum %v : %s", hopNum, orInfo.Address)
	}
	fmt.Printf("\n")
}

func (op OnionProxy) DialOR(ORAddr string) *rpc.Client {
	orServer, err := rpc.Dial("tcp", ORAddr)
	util.HandleFatalError("Could not dial shared_structs router", err)
	return orServer
}

func (s *OPServer) SendMessage(message string, ack *bool) error {
	chatMessage := shared_structs.ChatMessage {
		IRCServerAddr: s.OnionProxy.ircServerAddr,
		Username: s.OnionProxy.username,
		Message: message,
	}
	fmt.Printf("Recieved Message from Client for sending: %s \n", message)
	jsonData, _ := json.Marshal(&chatMessage)

	onion := s.OnionProxy.OnionizeData(jsonData)

	err := s.OnionProxy.SendChatMessageOnion(onion, s.OnionProxy.circId)
	*ack = true //TODO: change RPC response to chat history? error?
	return err
}

func (op OnionProxy) OnionizeData(coreData []byte) []byte {
	fmt.Printf("Start onionizing data \n")
	encryptedLayer := coreData

	for hopNum := len(op.ORInfoByHopNum)-1; hopNum >= 0; hopNum-- {
		unencryptedLayer := shared_structs.Onion{
			Data: encryptedLayer,
		}

		// If layer is meant for an exit node, turn IsExitNode flag on
		// Otherwise give it the address of the next OR o pass the shared_structs on to.
		if hopNum == len(op.ORInfoByHopNum)-1 {
			unencryptedLayer.IsExitNode = true
		} else {
			unencryptedLayer.NextAddress = op.ORInfoByHopNum[hopNum+1].Address
		}

		// json marshal the shared_structs layer
		jsonData, _ := json.Marshal(&unencryptedLayer)

		// Encrypt the shared_structs layer
		//TODO: create symmetric shared key with ORs in circuit
		key := []byte("0123456789123456")
		cipherkey, err := aes.NewCipher(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error from creating cipher: %s\n", err)
		}
		ciphertext := make([]byte, aes.BlockSize+len(jsonData))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			fmt.Fprintf(os.Stderr, "Error in reading iv: %s\n", err)
		}
		cfb := cipher.NewCFBEncrypter(cipherkey, iv)
		cfb.XORKeyStream(ciphertext[aes.BlockSize:], jsonData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		}

		fmt.Printf("Done onionizing data \n")

		encryptedLayer = ciphertext

	}
	return encryptedLayer
}


func (op OnionProxy) SendChatMessageOnion(onionToSend []byte, circId uint32) error {
	// Send shared_structs to the guardNode via RPC
	cell := shared_structs.Cell {
		CircId: circId,
		// Can add more in cell if each layer needs more info other (such as hopId)
		Data: onionToSend,
	}
	fmt.Printf("Sending shared_structs to guard node \n")
	var ack bool
	guardNodeRPCClient := op.DialOR(op.ORInfoByHopNum[0].Address)
	err := guardNodeRPCClient.Call("ORServer.DecryptChatMessageCell", cell, &ack)
	util.HandleFatalError("Could not send shared_structs to guard node", err)
	//TODO: handle error
	return err
}