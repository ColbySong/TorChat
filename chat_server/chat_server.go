package main

import (
	"net/rpc"
	"net"
	"fmt"
	"../util"
)

type CServer int

const (
	cserverPort string = ":12346"
)

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

// TODO: send ack message back to client, for now just print the message received
func (c *CServer) PublishMessage(msg string, ack *bool) error {
	fmt.Println(msg)
	return nil
}