# HTTP Server in GO

Http Server to parse Http request and process it 

# Quickstart

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

WEBSOCKET request: 

```console
curl -v -X GET http://localhost:8080 \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13"
```
