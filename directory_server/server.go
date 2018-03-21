//go run server.go
package main

import (
	"net"
	"sync"
	"net/rpc"
	"fmt"
	"time"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/rand"
)

type UnregisteredKeyError error
type NotEnoughORsError error

type DServer int

type OnionRouter struct {
	Address string
	MostRecentHeartBeat int64
}

type OnionRouterInfo struct {
	Address string
	PubKey  ecdsa.PublicKey
}

type ActiveORs struct {
	sync.RWMutex
	all map[string]*OnionRouter
}

var (
	// Directory Server Errors
	unregisteredKeyError UnregisteredKeyError = errors.New("Given Key is not registered")
	notEnoughORsError NotEnoughORsError = errors.New("Not enough ORs")

	// Server configurations
	serverPort string = ":12345"
	heartBeatInterval int64 = 2 // seconds
	numHops int = 3 // how many ORs will be in the circuit

	// All the active onion routers in the system mapped by pubKey
	activeORs ActiveORs = ActiveORs{all: make(map[string]*OnionRouter)}

)

func main() {
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

	pKey := pubKeyToString(or.PubKey)

	activeORs.all[pKey] = &OnionRouter{
		or.Address,
		time.Now().Unix(),
	}

        go monitor(pKey)
	fmt.Println("Got register from %s\n", or.Address)
	fmt.Println(activeORs.all)

	return nil
}

func (s *DServer) GetNodes(key ecdsa.PublicKey, addrSet *[]string) error {
	if len(activeORs.all) < numHops {
		return notEnoughORsError
	}

	activeORs.RLock()
	defer activeORs.RUnlock()

	pKey := pubKeyToString(key)

	if _, ok := activeORs.all[pKey]; !ok {
		return unregisteredKeyError
	}

	orAddresses := make([]string, len(activeORs.all) -1)

	for p, orAddress := range activeORs.all {
		if pKey == p {
			continue
		}
		orAddresses = append(orAddresses, orAddress.Address)
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

func (s *DServer) HeartBeat(key ecdsa.PublicKey, ack *bool) error {
	activeORs.Lock()
	defer activeORs.Unlock()

	pKey := pubKeyToString(key)

	if _, ok := activeORs.all[pKey]; !ok {
		return unregisteredKeyError
	}

	activeORs.all[pKey].MostRecentHeartBeat = time.Now().Unix()

	return nil
}

func printError(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
	}
}

func pubKeyToString(key ecdsa.PublicKey) string {
	return string(elliptic.Marshal(key.Curve, key.X, key.Y))
}

// removes dead ORs
func monitor(pKey string) {
	for {
		activeORs.Lock()
		if time.Now().Unix() - activeORs.all[pKey].MostRecentHeartBeat > heartBeatInterval {
			fmt.Println("%s timed out", activeORs.all[pKey].Address)
			delete(activeORs.all, pKey)
			activeORs.Unlock()
			return
		}
		fmt.Println("%s is alive", activeORs.all[pKey].Address)
		activeORs.Unlock()
		time.Sleep(time.Duration(heartBeatInterval)*time.Second)
	}
}