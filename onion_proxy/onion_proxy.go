package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"os"
	"time"

	"crypto/ecdsa"
	"errors"

	"../shared"
	"../util"
)

type NotTrustedDirectoryServerError error

type OPServer struct {
	OnionProxy *OnionProxy
}

type OnionProxy struct {
	addr           string
	username       string
	circuitId      uint32
	ircServerAddr  string
	ircServer      *rpc.Client
	ORInfoByHopNum map[int]*orInfo
	dirServer      *rpc.Client
	lastMessageId  uint32
}

type orInfo struct {
	address   string
	pubKey    *rsa.PublicKey
	sharedKey *[]byte
}

const (
	directoryServerPubKey string = "0449e30da789d5b12a9487a96d70d69b6b8cbd6821d7a647f35c18a8d5f0969054ae3130e7a2a813363eb578747bc77048b700badea328df20ce68a58fcd0e4166f538f9393e0b4072d069cc4cc631271660dc5ebebb20531f11eeb4bd5aa6a5ca"
)

var (
	notTrustedDirectoryServerError NotTrustedDirectoryServerError = errors.New("Circuit received from non-trusted directory server")
)

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

	ircServer, err := rpc.Dial("tcp", ircServerAddr)
	util.HandleFatalError("Could not dial irc server", err)

	addr, err := net.ResolveTCPAddr("tcp", opAddr)
	util.HandleFatalError("Could not resolve onion_proxy address", err)

	inbound, err := net.ListenTCP("tcp", addr)
	util.HandleFatalError("Could not listen", err)

	fmt.Println("OP Address: ", opAddr)
	fmt.Println("Full Address: ", inbound.Addr().String())

	ORInfoByHopNum := make(map[int]*orInfo)
	// Create OnionProxy instance
	onionProxy := &OnionProxy{
		addr:           opAddr,
		dirServer:      dirServer,
		ircServerAddr:  ircServerAddr,
		ORInfoByHopNum: ORInfoByHopNum,
		lastMessageId:  uint32(0),
		ircServer:      ircServer,
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
	if err := s.OnionProxy.GetNewCircuit(); err != nil {
		return err
	}
	//TODO: handle err

	// Then, start loop to establish new circuit every 2 mins
	go s.OnionProxy.GetNewCircuitEveryTwoMinutes()
	return nil
}

func (op *OnionProxy) GetNewCircuit() error {
	if err := op.GetCircuitFromDServer(); err != nil {
		return err
	}
	return nil
}

func (op *OnionProxy) GetNewCircuitEveryTwoMinutes() error {
	for {
		select {
		case <-time.After(120 * time.Second): //get new circuit after 2 minutes
			if err := op.GetCircuitFromDServer(); err != nil {
				return err
			}
		}
	}
}

func (op *OnionProxy) GetCircuitFromDServer() error {
	var n uint32
	binary.Read(rand.Reader, binary.LittleEndian, &n)
	op.circuitId = n

	var ORSet shared.OnionRouterInfos //ORSet can be a struct containing the OR address and pubkey
	err := op.dirServer.Call("DServer.GetNodes", "", &ORSet)
	util.HandleFatalError("Could not get circuit from directory server", err)
	util.OutLog.Println("New circuit recieved from directory server")

	// Verify that the circuit came from a trusted directory server
	if util.PubKeyToString(*ORSet.PubKey) != directoryServerPubKey || !ecdsa.Verify(ORSet.PubKey, ORSet.Hash, ORSet.SigR, ORSet.SigS) {
		return notTrustedDirectoryServerError
	}

	for hopNum, onionRouterInfo := range ORSet.ORInfos {
		sharedKey := util.GenerateAESKey()
		encryptedSharedKey := util.RSAEncrypt(onionRouterInfo.PubKey, sharedKey)

		circuitInfo := shared.CircuitInfo{
			CircuitId:          op.circuitId,
			EncryptedSharedKey: encryptedSharedKey,
		}

		client := op.DialOR(onionRouterInfo.Address)
		var ack bool
		client.Call("ORServer.SendCircuitInfo", circuitInfo, &ack)
		client.Close()
		util.OutLog.Printf("CircuitId %v, Shared Key: %s\n", circuitInfo.CircuitId, sharedKey)

		op.ORInfoByHopNum[hopNum] = &orInfo{
			address:   onionRouterInfo.Address,
			pubKey:    onionRouterInfo.PubKey,
			sharedKey: &sharedKey,
		}

		util.OutLog.Printf(" hopnum %v : %s", hopNum, onionRouterInfo.Address)
	}

	return nil
}

func (op *OnionProxy) DialOR(ORAddr string) *rpc.Client {
	orServer, err := rpc.Dial("tcp", ORAddr)
	util.HandleFatalError("Could not dial onion router", err)
	return orServer
}

func (s *OPServer) GetNewMessages(_ignored bool, resp *[]string) error {
	pollingMessage := shared.PollingMessage{
		IRCServerAddr: s.OnionProxy.ircServerAddr,
		LastMessageId: s.OnionProxy.lastMessageId,
	}
	jsonData, err := json.Marshal(&pollingMessage)
	util.HandleFatalError("Could not marshal polling message", err)

	onion := s.OnionProxy.OnionizeData(jsonData)

	messages, err := s.OnionProxy.SendPollingOnion(onion, s.OnionProxy.circuitId)
	util.HandleFatalError("Could not marshal polling message", err)

	s.OnionProxy.lastMessageId = s.OnionProxy.lastMessageId + uint32(len(messages))
	*resp = messages

	return nil
}

func (op *OnionProxy) SendPollingOnion(onionToSend []byte, circId uint32) ([]string, error) {
	// Send onion to the guardNode via RPC
	cell := shared.Cell{
		CircuitId: circId,
		Data:      onionToSend,
	}

	var messages []string
	guardNodeRPCClient := op.DialOR(op.ORInfoByHopNum[0].address)
	err := guardNodeRPCClient.Call("ORServer.DecryptPollingCell", cell, &messages)
	util.HandleFatalError("Could not send onion to guard node", err)
	guardNodeRPCClient.Close()

	return messages, nil
}

func (s *OPServer) SendMessage(message string, ack *bool) error {
	chatMessage := shared.ChatMessage{
		IRCServerAddr: s.OnionProxy.ircServerAddr,
		Username:      s.OnionProxy.username,
		Message:       message,
	}
	fmt.Printf("Recieved Message from Client for sending: %s \n", message)
	jsonData, err := json.Marshal(&chatMessage)
	util.HandleFatalError("Could not marshal chat message", err)

	onion := s.OnionProxy.OnionizeData(jsonData)

	err = s.OnionProxy.SendChatMessageOnion(onion, s.OnionProxy.circuitId)
	util.HandleFatalError("Could not send onion to guard node", err)

	*ack = true
	return nil
}

func (op *OnionProxy) OnionizeData(coreData []byte) []byte {
	encryptedLayer := coreData

	for hopNum := len(op.ORInfoByHopNum) - 1; hopNum >= 0; hopNum-- {
		unencryptedLayer := shared.Onion{
			Data: encryptedLayer,
		}

		// If layer is meant for an exit node, turn IsExitNode flag on
		// Otherwise give it the address of the next OR o pass the onion on to.
		if hopNum == len(op.ORInfoByHopNum)-1 {
			unencryptedLayer.IsExitNode = true
		} else {
			unencryptedLayer.NextAddress = op.ORInfoByHopNum[hopNum+1].address
		}

		// json marshal the onion layer
		jsonData, err := json.Marshal(&unencryptedLayer)
		util.HandleFatalError("Could not marshal unencrypted layer", err)

		// Encrypt the onion layer
		key := *op.ORInfoByHopNum[hopNum].sharedKey
		cipherkey, err := aes.NewCipher(key)
		util.HandleFatalError("Error creating cipher", err)

		ciphertext := make([]byte, aes.BlockSize+len(jsonData))
		prefix := ciphertext[:aes.BlockSize]
		_, err = io.ReadFull(rand.Reader, prefix)
		util.HandleFatalError("Error reading aes prefix", err)

		cfb := cipher.NewCFBEncrypter(cipherkey, prefix)
		cfb.XORKeyStream(ciphertext[aes.BlockSize:], jsonData)

		encryptedLayer = ciphertext
	}

	return encryptedLayer
}

func (op *OnionProxy) SendChatMessageOnion(onionToSend []byte, circId uint32) error {
	// Send onion to the guardNode via RPC
	cell := shared.Cell{ // Can add more in cell if each layer needs more info other (such as hopId)
		CircuitId: circId,
		Data:      onionToSend,
	}

	util.OutLog.Println("Sending onion to guard node")

	var ack bool
	guardNodeRPCClient := op.DialOR(op.ORInfoByHopNum[0].address)
	err := guardNodeRPCClient.Call("ORServer.DecryptChatMessageCell", cell, &ack)
	guardNodeRPCClient.Close()
	util.HandleFatalError("Could not send onion to guard node", err)

	return nil
}
