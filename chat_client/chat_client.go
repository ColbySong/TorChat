package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"os"
	"strconv"
	"strings"
	"time"

	"../util"
)

const LocalHostAddress = "127.0.0.1"
const PollingTime = 100

type ChatClient struct {
	Name   string
	Reader *bufio.Reader
	Proxy  *rpc.Client
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("What is your username? ")
	username := readInputLine(reader)
	fmt.Printf("Hello, %s.\n", username)

	client := ChatClient{
		username,
		reader,
		nil,
	}

	client.connectToProxy()

	go client.pollForNewMessages()
	client.getMessageInput()
}

func (client *ChatClient) connectToProxy() {
	// Prompt for and verify proxy port number
	fmt.Print("Proxy port: ")
	proxyPort := readInputLine(client.Reader)
	proxyPort = strings.TrimSpace(proxyPort)

	if !isValidPortNum(proxyPort) {
		log.Fatalf("\"%s\" is not a valid port\n", proxyPort)
	}

	// Establish bi-directional RPC connection with proxy
	laddr, err := net.ResolveTCPAddr("tcp", ":0")
	util.HandleFatalError("Cannot resolve address", err)

	proxyListener, err := net.ListenTCP("tcp", laddr)
	util.HandleFatalError("Cannot start listening for TCP", err)

	go client.startClientListen(proxyListener)

	proxyAddr := LocalHostAddress + ":" + proxyPort
	proxy, err := rpc.Dial("tcp", proxyAddr)
	util.HandleFatalError("Cannot connect to proxy", err)
	client.Proxy = proxy

	var resp bool // todo - should be error return type
	err = client.Proxy.Call("OPServer.Connect", client.Name, &resp)
	util.HandleFatalError("Cannot connect to proxy", err)

	fmt.Println("Client to Proxy connection established")
}

func (client *ChatClient) getMessageInput() {
	for {
		msg := readInputLine(client.Reader)

		var resp bool // todo - should be error return type
		client.Proxy.Call("OPServer.SendMessage", msg, &resp)
	}
}

func (client *ChatClient) pollForNewMessages() {
	for {
		var resp []string
		client.Proxy.Call("OPServer.GetNewMessages", true, &resp)
		displayMessages(resp)
		time.Sleep(time.Duration(PollingTime) * time.Millisecond)
	}
}

func displayMessages(messages []string) {
	for _, message := range messages {
		fmt.Println(message)
	}
}

// RPC endpoint
// Receive a new message from the proxy and display it on the terminal
func (client *ChatClient) PushNewMessage(msg string, resp *bool) error {
	log.Println(msg)
	*resp = true
	return nil
}

func (client *ChatClient) startClientListen(proxy *net.TCPListener) {
	conn, _ := proxy.Accept()
	fmt.Println("Proxy to Client connection established")
	clientRpcServer := rpc.NewServer()
	clientRpcServer.Register(client)
	clientRpcServer.ServeConn(conn)
}

func readInputLine(reader *bufio.Reader) string {
	str, _ := reader.ReadString('\n')
	return strings.TrimSpace(str)
}

func isValidPortNum(portNumStr string) bool {
	num, err := strconv.Atoi(portNumStr)
	if err == nil && num >= 0 && num <= 65535 {
		return true
	} else {
		return false
	}
}
