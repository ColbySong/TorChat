#!/usr/bin/env bash

# Start directory server
xterm -title 'Directory Server' -e 'go run ../directory_server/directory_server.go' &

# Start IRC server
xterm -title 'IRC server' -e 'go run ../chat_server/chat_server.go' &

# Pause to give servers time to start
sleep 3

# Start onion routers
xterm -title 'OR 0' -e 'go run ../onion_router/onion_router.go localhost:12345 127.0.0.1:8000' &
xterm -title 'OR 1' -e 'go run ../onion_router/onion_router.go localhost:12345 127.0.0.1:8001' &
xterm -title 'OR 2' -e 'go run ../onion_router/onion_router.go localhost:12345 127.0.0.1:8002' &
xterm -title 'OR 3' -e 'go run ../onion_router/onion_router.go localhost:12345 127.0.0.1:8003' &
xterm -title 'OR 4' -e 'go run ../onion_router/onion_router.go localhost:12345 127.0.0.1:8004' &

# Start onion proxy
xterm -title 'Onion Proxy' -e 'go run ../onion_proxy/onion_proxy.go localhost:12345 127.0.0.1:12346 127.0.0.1:9000' &

# Start chat client
xterm -title 'TorChat' -e 'go run ../chat_client/chat_client.go'
