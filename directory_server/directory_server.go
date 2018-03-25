//go run directory_server.go
package main

import (
	"crypto/elliptic"
	"encoding/gob"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/rpc"
	"sync"
	"time"
	"crypto/rsa"
)

type UnregisteredAddrError error
type NotEnoughORsError error

type DServer int

type OnionRouter struct {
	PubKey  rsa.PublicKey
	MostRecentHeartBeat int64
}

type OnionRouterInfo struct {
	Address string
	PubKey  rsa.PublicKey
}

type ActiveORs struct {
	sync.RWMutex
	all map[string]*OnionRouter
}

const (
	// Directory Server Errors
	unregisteredAddrError UnregisteredAddrError = errors.New("Given OR ip:port is not registered")
	notEnoughORsError    NotEnoughORsError    = errors.New("Not enough ORs")

	// Server configurations
	serverPort        string = ":12345"
	heartBeatInterval int64  = 2 // seconds
	numHops           int    = 3 // how many ORs will be in the circuit
)

var (
	// All the active onion routers in the system mapped by ip:port of OR
	activeORs ActiveORs = ActiveORs{all: make(map[string]*OnionRouter)}
)

func main() {
	gob.Register(&elliptic.CurveParams{})

	dserver := new(DServer)
	server := rpc.NewServer()
	server.Register(dserver)

	listener, err := net.Listen("tcp", serverPort)
	printError(err)
	fmt.Println("Server is listening on addr/port: ", listener.Addr(), "\n")

	for {
		conn, _ := listener.Accept()
		go server.ServeConn(conn)
	}
}

func (s *DServer) RegisterNode(or OnionRouterInfo, ack *bool) error {
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
func (s *DServer) GetNodes(_ignored string, addrSet *[]string) error {
	if len(activeORs.all) < numHops {
		return notEnoughORsError
	}

	activeORs.RLock()
	defer activeORs.RUnlock()

	orAddresses := make([]string, len(activeORs.all)-1)

	// list of all OR addresses
	for orAddress, _ := range activeORs.all {
		orAddresses = append(orAddresses, orAddress)
	}

	// return random array of OR IP addresses to be used in constructing circuit
	rand.Seed(time.Now().UnixNano())
	randomIndexes := rand.Perm(len(activeORs.all))

	var orCircuitIPs []string
	j := 0
	for _, i := range randomIndexes {
		orCircuitIPs[j] = orAddresses[i]
		j++
	}

	*addrSet = orCircuitIPs[:numHops]

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
