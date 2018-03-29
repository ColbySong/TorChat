//go run directory_server.go
package main

import (
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/gob"
	"errors"
	"fmt"
	math_rand "math/rand"
	"net"
	"net/rpc"
	"sync"
	"time"

	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"

	"../shared"
	"../util"
)

type UnregisteredAddrError error
type NotEnoughORsError error

type DServer int

type OnionRouter struct {
	PubKey              *rsa.PublicKey
	MostRecentHeartBeat int64
}

type ActiveORs struct {
	sync.RWMutex
	all map[string]*OnionRouter
}

const (
	// Server configurations
	privKeyStr        string = "3081a40201010430aeb7b244cf5ee8a952ff378a140275a0d7f98a7c44faca12357867c667b860fa2aaf7bf9039d3b481479bf0fd512097fa00706052b81040022a1640362000449e30da789d5b12a9487a96d70d69b6b8cbd6821d7a647f35c18a8d5f0969054ae3130e7a2a813363eb578747bc77048b700badea328df20ce68a58fcd0e4166f538f9393e0b4072d069cc4cc631271660dc5ebebb20531f11eeb4bd5aa6a5ca"
	serverPort        string = ":12345"
	heartBeatInterval int64  = 2 // seconds
	numHops           int    = 3 // how many ORs will be in the circuit
)

var (
	// Directory Server Errors
	unregisteredAddrError UnregisteredAddrError = errors.New("Given OR ip:port is not registered")
	notEnoughORsError     NotEnoughORsError     = errors.New("Not enough ORs")

	// All the active onion routers in the system mapped by ip:port of OR
	activeORs ActiveORs = ActiveORs{all: make(map[string]*OnionRouter)}

	pubKey  ecdsa.PublicKey
	privKey *ecdsa.PrivateKey
)

func main() {
	gob.Register(&elliptic.CurveParams{})

	dserver := new(DServer)
	server := rpc.NewServer()
	server.Register(dserver)

	// Decode keys from strings
	var err error
	privKeyBytesRestored, _ := hex.DecodeString(privKeyStr)
	privKey, err = x509.ParseECPrivateKey(privKeyBytesRestored)
	util.HandleFatalError("Can not parse private key", err)
	pubKey = privKey.PublicKey

	listener, err := net.Listen("tcp", serverPort)
	printError(err)
	fmt.Println("Server is listening on addr/port: ", listener.Addr(), "\n")

	for {
		conn, _ := listener.Accept()
		go server.ServeConn(conn)
	}
}

func (s *DServer) RegisterNode(or shared.OnionRouterInfo, ack *bool) error {
	activeORs.Lock()
	defer activeORs.Unlock()

	activeORs.all[or.Address] = &OnionRouter{
		or.PubKey,
		time.Now().Unix(),
	}

	go monitor(or.Address)
	fmt.Printf("Got register from %s\n", or.Address)

	return nil
}

// The RPC call to GetNodes does not require any arguments
func (s *DServer) GetNodes(_ignored string, dsORSet *shared.OnionRouterInfos) error {
	if len(activeORs.all) < numHops {
		return notEnoughORsError
	}

	activeORs.RLock()
	defer activeORs.RUnlock()

	var orAddresses []string

	// list of all OR addresses
	for orAddress, _ := range activeORs.all {
		orAddresses = append(orAddresses, orAddress)
	}

	// return random array of OR IP addresses to be used in constructing circuit
	math_rand.Seed(time.Now().UnixNano())
	randomIndexes := math_rand.Perm(len(activeORs.all))

	var orInfos []shared.OnionRouterInfo
	for i := 0; i < numHops; i++ {
		randomORip := orAddresses[randomIndexes[i]]
		orInfos = append(orInfos, shared.OnionRouterInfo{
			Address: randomORip,
			PubKey:  activeORs.all[randomORip].PubKey,
		})
	}

	orBytes, err := json.Marshal(orInfos)
	util.HandleFatalError("error marshalling OR info", err)
	hash := md5.New()
	hash.Write(orBytes)
	hashBytes := hash.Sum(nil)

	// sign the hash
	sigR, sigS, _ := ecdsa.Sign(rand.Reader, privKey, hashBytes)

	dsORInfo := shared.OnionRouterInfos{
		SigS:    sigS,
		SigR:    sigR,
		Hash:    hashBytes,
		PubKey:  &pubKey,
		ORInfos: orInfos[:numHops],
	}

	*dsORSet = dsORInfo
	fmt.Printf("New Circuit: %v ", *dsORSet)

	return nil
}

func (s *DServer) KeepNodeOnline(orAddress string, ack *bool) error {
	activeORs.Lock()
	defer activeORs.Unlock()

	if _, ok := activeORs.all[orAddress]; !ok {
		return unregisteredAddrError
	}

	activeORs.all[orAddress].MostRecentHeartBeat = time.Now().Unix()

	return nil
}

func printError(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
	}
}

// removes dead ORs
func monitor(orAddress string) {
	for {
		activeORs.Lock()
		if time.Now().Unix()-activeORs.all[orAddress].MostRecentHeartBeat > heartBeatInterval {
			fmt.Printf("%s timed out\n", orAddress)
			delete(activeORs.all, orAddress)
			activeORs.Unlock()
			return
		}
		fmt.Printf("%s is alive\n", orAddress)
		activeORs.Unlock()
		time.Sleep(time.Duration(heartBeatInterval) * time.Second)
	}
}
