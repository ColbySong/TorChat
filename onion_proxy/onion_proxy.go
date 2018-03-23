package onion_proxy

import (
	"crypto/ecdsa"
	"encoding/gob"
	"net"
	"crypto/elliptic"
	"flag"
	"fmt"
	"os"
	"../util"

	"net/rpc"
	"crypto/sha256"
	"crypto/rsa"
	"encoding/json"
	"../cells"
)

type OPServer struct {
	OnionProxy *OnionProxy
}

// TODO: need global var to keep hopId for all instances of OP

type OnionProxy struct {
	hopId int
	addr string
	ircServerAddr string
	username string
	ORInfoByHopNum map[int]ORInfo
	dirServer *rpc.Client
	guardNodeServer *rpc.Client
}

type ORInfo struct {
	addr string
	pubKey *ecdsa.PublicKey
}


// Example Commands
// go run onion_proxy.go localhost:12345 127.0.0.1:9000 127.0.0.1:8000
// go run onion_proxy.go localhost:12345 127.0.0.1:9000 127.0.0.1:8001

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	// Command line input parsing
	flag.Parse()
	if len(flag.Args()) != 3 {
		fmt.Fprintln(os.Stderr, "go run onion_proxy.go [dir-server ip:port] [op ip:port] [privKey]")
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

	//TODO: get addr and pub keys from dir-server
	addrSet := onionProxy.GetNodes()

	// Start listening for RPC calls from ORs
	opServer := new(OPServer)
	opServer.OnionProxy = onionProxy

	onionProxyServer := rpc.NewServer()
	onionProxyServer.Register(opServer)

	util.HandleFatalError("Listen error", err)
	util.OutLog.Printf("OPServer started. Receiving on %s\n", opAddr)

	opServer.CreateCircuit(addrSet)

	// new OP connection for each incoming client
	for {
		conn, _ := inbound.Accept()
		go onionProxyServer.ServeConn(conn)
	}

}

func (op OnionProxy) GetNodes() []string {
	//TODO: do i need to provide pubkey to GetNodes as an OP?
	//TODO: can i just get the pubKey from the ORAddrSet?
	var ORAddressSet []string
	op.dirServer.Call("DServer.GetNodes", nil, &ORAddressSet)
	return ORAddressSet
}

func (op OnionProxy) DialOR(ORAddr string) *rpc.Client{
	orServer, err := rpc.Dial("tcp", ORAddr)
	util.HandleFatalError("Could not dial OR", err)
	return orServer
}


func (op OnionProxy) SendOnion(onion []byte) error {
	// Send onion to the guardNode via RPC
	cell := cells.CellStruct {
		FromAddr: op.addr,
		FromHopId: op.hopId,
		Data: onion,
	}
	var ack bool
	err := op.guardNodeServer.Call("ORServer.DecryptCell", cell, &ack)
	return nil
}

func (s *OPServer) CreateCircuit(ORInfos []string) error {
	var addrSet = make([]string, len(ORInfos))
	for hopNum, addr := range addrSet {
		s.OnionProxy.ORInfoByHopNum[hopNum] = ORInfo{
			addr: ORInfos.addr,
			pubKey: ORInfos.pubkey,
		}
	}
	onion := s.OnionProxy.OnionizeData(cells.CREATE, nil)
	err := s.OnionProxy.SendOnion(onion)
	return err
}

func (s *OPServer) Connect(username string) error {
	s.OnionProxy.username = username


	ircServerAddr := []byte(s.OnionProxy.ircServerAddr)

	onion := s.OnionProxy.OnionizeData(cells.DATA, ircServerAddr)

	guardNode := s.OnionProxy.ORInfoByHopNum[0]
	orServer := s.OnionProxy.DialOR(guardNode.addr)
	s.OnionProxy.guardNodeServer = orServer

	s.OnionProxy.SendOnion(onion)

	return nil
}

func (s *OPServer) SendMessage(message string, chatHistory *string) error {

	chatMessage := []byte(s.OnionProxy.username + ": "+ message)

	onion := s.OnionProxy.OnionizeData(cells.DATA, chatMessage)

	err := s.OnionProxy.SendOnion(onion)
	return err
}

func (op OnionProxy) OnionizeData(dataType cells.DataType, data []byte) []byte {
	encryptedData := data
	for hopNum := len(op.ORInfoByHopNum); hopNum < 0; hopNum-- {
		unencryptedData := cells.DataWithPayload{
			DataType: dataType,
			Data: encryptedData,
		}

		//CREATE specifics
		if dataType == cells.CREATE {
			if hopNum == len(op.ORInfoByHopNum) {
				unencryptedData.Flag = true
			}
			if hopNum < len(op.ORInfoByHopNum) {
				unencryptedData.Label = op.ORInfoByHopNum[hopNum].addr
			}
		}

		jsonData, _ := json.Marshal(&unencryptedData)

		pubKeyOfOR := op.ORInfoByHopNum[hopNum].pubKey
		encryptedData, _ = rsa.EncryptOAEP(sha256.New(), nil, pubKeyOfOR, jsonData, nil)
		return encryptedData
	}

}