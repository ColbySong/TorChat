package main

import (
	"fmt"
	"net"
	"net/rpc"
	"sync"

	"../util"
)

type CServer int

const (
	cserverPort string = ":12346"
)

type AllMessages struct {
	sync.RWMutex
	all []string
}

var messages = AllMessages{all: make([]string, 0)}

// go run chat_server.go
func main() {
	cserver := new(CServer)
	server := rpc.NewServer()
	server.Register(cserver)

	listener, err := net.Listen("tcp", cserverPort)
	util.HandleFatalError("Error starting server", err)
	fmt.Println("Server is listening on addr/port: ", listener.Addr(), "\n")

	for {
		conn, err := listener.Accept()
		util.HandleFatalError("Error accepting", err)
		go server.ServeConn(conn)
	}
}

func (c *CServer) PublishMessage(msg string, ack *bool) error {
	messages.Lock()
	defer messages.Unlock()

	messages.all = append(messages.all, msg)
	fmt.Println(msg)

	*ack = true
	return nil
}

func (c *CServer) GetNewMessages(last uint32, resp *[]string) error {
	messages.RLock()
	defer messages.RUnlock()

	temp := make([]string, len(messages.all))
	copy(temp, messages.all)
	*resp = temp[last:]

	return nil
}
