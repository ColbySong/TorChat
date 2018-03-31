package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
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

	util.OutLog.Println("OP Address: ", opAddr)
	util.OutLog.Println("Full Address: ", inbound.Addr().String())

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

	util.OutLog.Printf("Client username: %s \n", username)

	// First, wait to establish first new circuit
	if err := s.OnionProxy.GetNewCircuit(); err != nil {
		util.HandleNonFatalError("Could not create new circuit", err)
		return err
	}

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
				util.HandleNonFatalError("Could not create new circuit", err)
				return err
			}
		}
	}
}

func (op *OnionProxy) GetCircuitFromDServer() error {
	util.OutLog.Println("Generating new circuit...")
	var n uint32
	binary.Read(rand.Reader, binary.LittleEndian, &n)
	op.circuitId = n

	var ORSet shared.OnionRouterInfos //ORSet can be a struct containing the OR address and pubkey
	err := op.dirServer.Call("DServer.GetNodes", "", &ORSet)
	util.HandleFatalError("Could not get circuit from directory server", err)

	// Verify that the circuit came from a trusted directory server
	if util.PubKeyToString(*ORSet.PubKey) != directoryServerPubKey || !ecdsa.Verify(ORSet.PubKey, ORSet.Hash, ORSet.SigR, ORSet.SigS) {
		return notTrustedDirectoryServerError
	}

	for hopNum, onionRouterInfo := range ORSet.ORInfos {
		sharedKey := util.GenerateAESKey()
		encryptedSharedKey, err := util.RSAEncrypt(onionRouterInfo.PubKey, sharedKey)
		if err != nil {
			util.HandleNonFatalError("Could not encrypt shared key", err)
			return err
		}

		circuitInfo := shared.CircuitInfo{
			CircuitId:          op.circuitId,
			EncryptedSharedKey: encryptedSharedKey,
		}

		client, err := op.DialOR(onionRouterInfo.Address)
		if err != nil {
			return err
		}

		var ack bool
		if err := client.Call("ORServer.SendCircuitInfo", circuitInfo, &ack); err != nil {
			util.HandleNonFatalError("Could not send circuit info to ORs", err)
			return err
		}
		client.Close()

		op.ORInfoByHopNum[hopNum] = &orInfo{
			address:   onionRouterInfo.Address,
			pubKey:    onionRouterInfo.PubKey,
			sharedKey: &sharedKey,
		}

		util.OutLog.Printf("\nCircuitId %v:\n    Hop Number: %v\n    OR Address: %s\n    Shared Key: %s\n", circuitInfo.CircuitId, hopNum+1, onionRouterInfo.Address, hex.EncodeToString(sharedKey))
	}

	util.OutLog.Println("Circuit generation completed")

	return nil
}

func (op *OnionProxy) DialOR(ORAddr string) (*rpc.Client, error) {
	orServer, err := rpc.Dial("tcp", ORAddr)
	if err != nil {
		util.HandleNonFatalError("Could not dial onion router: "+ORAddr, err)
		return nil, err
	}
	return orServer, nil
}

func (s *OPServer) GetNewMessages(_ignored bool, resp *[]string) error {
	pollingMessage := shared.PollingMessage{
		IRCServerAddr: s.OnionProxy.ircServerAddr,
		LastMessageId: s.OnionProxy.lastMessageId,
	}
	jsonData, err := json.Marshal(&pollingMessage)
	if err != nil {
		util.HandleFatalError("Could not retrieve new messages", err)
		return err
	}

	onion, err := s.OnionProxy.OnionizeData(jsonData)
	if err != nil {
		util.HandleFatalError("Could not retrieve new messages", err)
		return err
	}

	messages, err := s.OnionProxy.SendPollingOnion(onion, s.OnionProxy.circuitId)
	if err != nil {
		util.HandleFatalError("Could not retrieve new messages", err)
		return err
	}

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
	guardNodeRPCClient, err := op.DialOR(op.ORInfoByHopNum[0].address)
	if err != nil {
		return nil, err
	}

	err = guardNodeRPCClient.Call("ORServer.DecryptPollingCell", cell, &messages)
	if err != nil {
		util.HandleNonFatalError("Could not send onion to guard node", err)
		return nil, err
	}
	guardNodeRPCClient.Close()

	return messages, nil
}

func (s *OPServer) SendMessage(message string, ack *bool) error {
	chatMessage := shared.ChatMessage{
		IRCServerAddr: s.OnionProxy.ircServerAddr,
		Username:      s.OnionProxy.username,
		Message:       message,
	}

	util.OutLog.Printf("Recieved Message from Client for sending: %s \n", message)

	jsonData, err := json.Marshal(&chatMessage)
	if err != nil {
		util.HandleNonFatalError("Could not send message", err)
		return err
	}

	onion, err := s.OnionProxy.OnionizeData(jsonData)
	if err != nil {
		util.HandleNonFatalError("Could not send message", err)
		return err
	}

	if err = s.OnionProxy.SendChatMessageOnion(onion, s.OnionProxy.circuitId); err != nil {
		util.HandleNonFatalError("Could not send message", err)
		return err
	}

	util.OutLog.Println("Message successfully sent!")

	*ack = true
	return nil
}

func (op *OnionProxy) OnionizeData(coreData []byte) ([]byte, error) {
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
		if err != nil {
			return nil, err
		}

		// Encrypt the onion layer
		key := *op.ORInfoByHopNum[hopNum].sharedKey
		cipherkey, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		ciphertext := make([]byte, aes.BlockSize+len(jsonData))
		prefix := ciphertext[:aes.BlockSize]
		if _, err = io.ReadFull(rand.Reader, prefix); err != nil {
			return nil, err
		}

		cfb := cipher.NewCFBEncrypter(cipherkey, prefix)
		cfb.XORKeyStream(ciphertext[aes.BlockSize:], jsonData)

		encryptedLayer = ciphertext
	}

	return encryptedLayer, nil
}

func (op *OnionProxy) SendChatMessageOnion(onionToSend []byte, circId uint32) error {
	// Send onion to the guardNode via RPC
	cell := shared.Cell{ // Can add more in cell if each layer needs more info other (such as hopId)
		CircuitId: circId,
		Data:      onionToSend,
	}

	util.OutLog.Println("Sending onion to guard node")

	var _ignored bool
	guardNodeRPCClient, err := op.DialOR(op.ORInfoByHopNum[0].address)
	if err != nil {
		return err
	}

	if err := guardNodeRPCClient.Call("ORServer.DecryptChatMessageCell", cell, &_ignored); err != nil {
		util.HandleNonFatalError("Could not send onion through onion network", err)
		return err
	}
	guardNodeRPCClient.Close()

	return nil
}
