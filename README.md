# HTTP Server in GO

HTTP Server to parse HTTP request and process it 
Websocket sit on top of HTTP server to echo back frame
Perform TLS handshake before the HTTP request to secure the connection

The HTTP server now default to serve securely so if want to perform quickstart guide, please change the IsSecure variable from true to false then rerun go build command

## Quickstart

Open 1 terminal for the server
```console
go build main.go && ./main
```

Open another terminal to send request

GET request:
```console
curl localhost:8080
```

POST request with json body:
```console
curl -d '{"go": "good", "zig": "better"}' -H "Content-Type: application/json" localhost:8080
```

POST request with raw binary image body:
```console
curl --data-binary @{YOUR_IMAGE_PATH} -H "Content-Type: image/jpeg" localhost:8080
```

WEBSOCKET request (test request): 

```console
curl -v -X GET http://localhost:8080 \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13"
```

WEBSOCKET request (interactive): 

required: websocat 

for fedora: 
```console
sudo dnf copr enable atim/websocat -y
sudo dnf install websocat -y
```

then run 
```console
websocat ws://localhost:8080
```
then chat and the server will echo the message

press Ctrl+D to send close opcode and close connection

## Secure connection

required: mkcert (to create a self-signed certificate), nss-tools (for chrome, firefox)

for fedora:

```console
sudo dnf install mkcert nss-tools
mkcert -install
```

then in the project directory, run:

```console
mkcert localhost
```

Open 1 terminal for the server
```console
go build main.go && ./main
```

Open another terminal to send request

GET request:
```console
curl https://localhost:8080
```

WEBSOCKET request (interactive): 
```console
websocat wss://localhost:8080
```

