package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RequestLine struct {
	HTTPVersion   string
	RequestTarget string
	Method        string
}

type Request struct {
	RequestLine RequestLine
	Header      map[string]string
	Body        map[string]any
}

type WebsocketFrame struct {
	IsFinal bool
	OpCode  byte
	IsMask  bool
	Length  uint64
	MaskKey [4]byte
	PayLoad []byte
}

type state int

const (
	parseMethod state = iota
	parseResource
	parseVersion
	parseKey
	parseValue
	parseBodyJSON
	parseBodyImageBin
	expectLF
	expectSpace
	end
)

type frameState int

const (
	parseFin frameState = iota
	parseOpCode
	parseMask
	parseLength
	parseLength16
	parseLength64
	parseFrameKey
	parsePayload
	endFrame
)

const (
	OpContinuation byte = 0x00
	OpText         byte = 0x01
	OpBinary       byte = 0x02
	OpClose        byte = 0x08
	OpPing         byte = 0x09
	OpPong         byte = 0x0A
)

// Create a global pool for 1024-byte buffers
var bufferPool = sync.Pool{
	New: func() any {
		// This runs only when the pool is completely empty
		b := make([]byte, 1024)
		return &b // Return a pointer to avoid copying the slice header
	},
}

const UploadImagesFolder = "upload_images"
const FileNameLength = 8
const Host = "localhost:8080"

func main() {
	fmt.Println("Hello, World!")
	fmt.Printf("Server listen on: %s\n", Host)
	server, err := net.Listen("tcp", Host)
	if err != nil {
		fmt.Printf("failed to bind to %s: %s", Host, err)
		os.Exit(1)
	}

	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Printf("can't open file, err: %s", err)
			// if err just continue
			continue
		}

		go handleClient(connection)

	}
}

func createWebSocketOKResponse(base64Encode string) []byte {
	// Generates: "Sun, 12 Jul 2026 13:45:00 GMT"
	dateStr := time.Now().UTC().Format(time.RFC1123)
	// Double quotes allow \r\n escape characters.
	// Note the double \r\n\r\n at the very end to signal the end of HTTP headers.
	result := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Date: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"Sec-WebSocket-Protocol: chat\r\n\r\n",
		dateStr, base64Encode,
	)
	return []byte(result)
}

func createServerErrorResponse(err error) []byte {
	// Generates: "Sun, 12 Jul 2026 13:45:00 GMT"
	dateStr := time.Now().UTC().Format(time.RFC1123)
	// It is safer to generate the JSON body first, then calculate its exact length dynamically.
	body := fmt.Sprintf(`{"error": "InternalServerError", "message": "%s"}`, err.Error())

	result := fmt.Sprintf(
		"HTTP/1.1 500 Internal Server Error\r\n"+
			"Date: %s\r\n"+
			"Content-Type: application/json; charset=UTF-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n"+
			"%s",
		dateStr, len(body), body,
	)
	return []byte(result)
}
func createBadRequestResponse(err error) []byte {
	// Generates: "Sun, 12 Jul 2026 13:45:00 GMT"
	dateStr := time.Now().UTC().Format(time.RFC1123)
	body := fmt.Sprintf(`{"error": "BadRequest", "message": "%s"}`, err.Error())

	result := fmt.Sprintf(
		"HTTP/1.1 400 Bad Request\r\n"+
			"Date: %s\r\n"+
			"Content-Type: application/json; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n"+
			"%s",
		dateStr, len(body), body,
	)
	return []byte(result)
}

func createOKResponse() []byte {
	// Generates: "Sun, 12 Jul 2026 13:45:00 GMT"
	dateStr := time.Now().UTC().Format(time.RFC1123)
	body := `{"status": "success", "message": "hello"}`

	result := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Date: %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n\r\n"+
			"%s",
		dateStr, len(body), body,
	)
	return []byte(result)
}

func handleClient(con net.Conn) {
	contents, err := parseHTTPWithFSM(con)
	if err != nil {
		errorResponse := createServerErrorResponse(err)
		_, err = con.Write(errorResponse)
		if err != nil {
			_, _ = fmt.Printf("can't send response, err: %s", err)
			return
		}
	}

	fmt.Printf("Request: %#v\n", contents)

	allowedMethod := []string{"GET", "POST", "QUERY"}
	method := contents.RequestLine.Method

	if !slices.Contains(allowedMethod, method) {
		_, _ = fmt.Printf("method %s not allowed", method)
		err = fmt.Errorf("method %s not allowed", method)
		errorResponse := createBadRequestResponse(err)
		_, err = con.Write(errorResponse)
		if err != nil {
			_, _ = fmt.Printf("can't send response, err: %s", err)
			return
		}
	}

	fmt.Printf("body is: %v\n", contents.Body)

	connection, ok := contents.Header["connection"]
	if ok {
		if connection == "Upgrade" {
			_ = handleUpgradeConnection(contents, con)
			//hand off the connection to the upgraded one
			return
		}
	}

	// responding
	response := createOKResponse()

	_, err = con.Write(response)
	if err != nil {
		_, _ = fmt.Printf("can't send response, err: %s", err)
		return
	}
}

func handleUpgradeConnection(request *Request, con net.Conn) error {
	upgrade, ok := request.Header["upgrade"]
	if !ok {
		return fmt.Errorf("need to specify the upgrade protocol name")
	}
	if upgrade == "websocket" {
		code, err := handleWebsocketCon(request, con)
		if err != nil {
			errorResponse := []byte{}
			fmt.Println(string(errorResponse))
			// just log internally, and close the connection
			return err
		}

		if code == 200 {
			fmt.Println("Send close signal")
			frame := WebsocketFrame{}
			frame.IsFinal = true
			frame.OpCode = OpClose
			frame.IsMask = false

			frame.PayLoad = []byte{}
			data := []byte("goodbye")
			statusCode := uint16(1000)
			//closing need to take the first 2 byte
			statusCodeBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(statusCodeBytes, statusCode)
			frame.PayLoad = append(frame.PayLoad, statusCodeBytes...)
			frame.PayLoad = append(frame.PayLoad, data...)

			frame.Length = uint64(len(frame.PayLoad))

			err := writeWebsocketFrame(con, frame)
			if err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("upgrade protocol not allowed: %s", upgrade)
	}
	return nil
}

func writeWebsocketFrame(con net.Conn, frame WebsocketFrame) error {
	// fin and opcode
	message := []byte{}
	firstByte := byte(0b00)

	if frame.IsFinal {
		firstByte = 1 << 7
	}
	firstByte = firstByte | frame.OpCode
	message = append(message, firstByte)

	//message from server never mask

	if frame.Length < 126 {
		// small payload
		message = append(message, byte(frame.Length))
	} else if frame.Length <= 65535 {
		// medium payload, set flag as 126
		message = append(message, 126)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(frame.Length))
		message = append(message, lenBytes...)
	} else {
		// large payload, set flag as 127
		message = append(message, 127)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, frame.Length)
	}

	message = append(message, frame.PayLoad...)

	_, err := con.Write([]byte(message))
	if err != nil {
		return err
	}
	return nil
}

func handleWebsocketCon(request *Request, con net.Conn) (int, error) {
	method := request.RequestLine.Method
	if method != "GET" {
		return 405, fmt.Errorf("method not allowed for websocket: %s, expedted GET", method)
	}
	header := request.Header
	host, ok := header["host"]
	if !ok {
		return 400, fmt.Errorf("missing header, expected host")
	}
	secWebSocketKey, ok := header["sec-websocket-key"]
	if !ok {
		return 400, fmt.Errorf("missing header, expected sec-websocket-key")
	}
	secWebSocketVersion, ok := header["sec-websocket-version"]
	if !ok {
		return 400, fmt.Errorf("missing header, expected sec-websocket-version")
	}

	if host != Host {
		return 400, fmt.Errorf("connect to wrong host")
	}

	if !isValidBase64([]byte(secWebSocketKey)) {
		return 400, fmt.Errorf("websocket key is not a valid base64")
	}

	if secWebSocketVersion != "13" {
		return 400, fmt.Errorf("websocket version is not supported")
	}

	fmt.Println("succesfully validate the request")

	magicString := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	concatenateString := secWebSocketKey + magicString
	sha1Hash := sha1.Sum([]byte(concatenateString))
	base64Encode := base64.StdEncoding.EncodeToString(sha1Hash[:])
	response := createWebSocketOKResponse(base64Encode)
	_, err := con.Write(response)
	if err != nil {
		_, _ = fmt.Printf("can't send response, err: %s", err)
		return 500, err
	}

	for {
		frame, err := parseWebsocketFrame(con)
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Println("Client disconnected cleanly (EOF)")
				return 200, nil
			}
			return 500, err
		}
		returnFrame := *frame
		returnFrame.PayLoad = append([]byte("Simon say: "), frame.PayLoad...)
		returnFrame.Length = uint64(len(returnFrame.PayLoad))
		writeWebsocketFrame(con, returnFrame)
		fmt.Printf("frame is %+v\n", frame)
		if frame.OpCode == OpText {
			fmt.Printf("Message is: %s", string(frame.PayLoad))
		}
		if frame.OpCode == OpClose {
			fmt.Println("close connection now")
			break
		}
	}

	return 200, nil
}

func parseWebsocketFrame(con net.Conn) (*WebsocketFrame, error) {
	fmt.Println("Start parsing websocketframe")

	// 1. Borrow a buffer pointer from the pool
	bufPtr := bufferPool.Get().(*[]byte)

	// 2. Ensure it goes back to the pool when this function returns
	defer bufferPool.Put(bufPtr)

	// 3. Dereference it locally so you can use it exactly like before
	readBuffer := *bufPtr

	//before:
	// readBuffer := make([]byte, 1024)

	endParsing := false
	frame := &WebsocketFrame{}
	s := parseFin
	var cumLength uint64 = 0
	count := 0
	maskKey := [4]byte{}
	keyCount := 0
	rest := 0
	cumPayload := []byte{}

ReadBufferLoop:
	for !endParsing {
		bytes, err := con.Read(readBuffer)
		if err != nil {
			return nil, err
		}
		fmt.Printf("read %d\n", bytes)

		i := 0
		for i < bytes {
			char := readBuffer[i]
			switch s {
			case parseFin:
				// get the first bit
				fin := char >> 7
				frame.IsFinal = (fin == 0x01)
				s = parseOpCode
				//reuse the same byte
				continue
			case parseOpCode:
				// get the last 4 bits
				opcode := char & 0b00001111
				frame.OpCode = opcode
				s = parseMask
				if opcode == OpClose {
					return frame, nil
				}

			case parseMask:
				mask := char >> 7
				frame.IsMask = (mask == 0x01)
				if !frame.IsMask {
					return nil, fmt.Errorf("protocol error: client frame must be masked")
				}
				s = parseLength
				continue // continue to reuse the same byte (for next parsing step)
			case parseLength:
				length := char & 0b01111111
				if length < 126 {
					frame.Length = uint64(length)
					rest = int(frame.Length)
					s = parseFrameKey
				} else if length == 126 {
					s = parseLength16
					cumLength = 0
				} else {
					s = parseLength64
					cumLength = 0
				}
			case parseLength16:
				count += 1
				cumLength = (cumLength << 8) | uint64(char)

				if count == 2 {
					s = parseFrameKey
					frame.Length = cumLength
					rest = int(frame.Length)
				}
			case parseLength64:
				count += 1
				cumLength = (cumLength << 8) | uint64(char)

				if count == 8 {
					s = parseFrameKey
					frame.Length = cumLength
					rest = int(frame.Length)
				}

			case parseFrameKey:
				if !frame.IsMask {
					frame.MaskKey = [4]byte{}
					s = parsePayload
				} else {
					key := char
					maskKey[keyCount] = key
					keyCount += 1
					if keyCount == 4 {
						frame.MaskKey = maskKey
						s = parsePayload
					}
				}

			case parsePayload:
				bytesLeft := bytes - i
				if rest > bytesLeft {
					rest = rest - bytesLeft
					cumPayload = append(cumPayload, readBuffer[i:]...)
					continue ReadBufferLoop
				} else {
					cumPayload = append(cumPayload, readBuffer[i:i+rest]...)
					unmaskPayLoad(&cumPayload, frame.MaskKey, int(frame.Length))
					frame.PayLoad = cumPayload
					fmt.Println("End now")
					endParsing = true
				}
			}
			i++
		}
	}
	return frame, nil
}

func unmaskPayLoad(payload *[]byte, key [4]byte, length int) {
	for i := range length {
		byte := (*payload)[i]
		maskKey := key[i%4]
		(*payload)[i] = byte ^ maskKey
	}
}

func isValidBase64(key []byte) bool {
	//simple check (idc if they have special character)

	if len(key) != 24 {
		return false
	}
	if !bytes.HasSuffix(key, []byte("==")) {
		return false
	}

	return true

}

func parseHTTPWithFSM(con net.Conn) (*Request, error) {
	fmt.Println("parsing nowwww")
	// 1. Borrow a buffer pointer from the pool
	bufPtr := bufferPool.Get().(*[]byte)

	// 2. Ensure it goes back to the pool when this function returns
	defer bufferPool.Put(bufPtr)

	// 3. Dereference it locally so you can use it exactly like before
	buffer := *bufPtr

	//before
	// buffer := make([]uint8, 1024)

	s := parseMethod
	var nextState state
	request := &Request{}
	fields := map[string]string{}
	requestLine := RequestLine{}
	key := ""
	readBuffer := []byte{}

	jsonStr := []byte{}
	count := 0

	bodyRead := 0
	imageBody := []uint8{}

OuterLoop:
	for {
		bytes, err := con.Read(buffer)
		if bytes <= 0 {
			break
		}
		if err != nil {
			_, _ = fmt.Printf("can't read file, err: %s", err)
			return nil, err
		}

	StateMachineLoop:
		for i := range bytes {
			char := buffer[i]
			switch s {
			case parseMethod:
				if char == ' ' {
					requestLine.Method = string(readBuffer)
					readBuffer = []byte{}
					s = parseResource
				} else {
					readBuffer = append(readBuffer, char)
				}
			case parseResource:
				if char == ' ' {
					requestLine.RequestTarget = string(readBuffer)
					readBuffer = []byte{}
					s = parseVersion
				} else {
					readBuffer = append(readBuffer, char)
				}

			case parseVersion:
				if char == '\r' {
					requestLine.HTTPVersion = string(readBuffer)
					readBuffer = []byte{}
					s = expectLF
					nextState = parseKey //state after the next state
				} else {
					readBuffer = append(readBuffer, char)
				}
			case expectLF:
				if char == '\n' {
					s = nextState
					request.RequestLine = requestLine
					request.Header = fields
					if nextState == end {
						request.Body = nil
						break OuterLoop
					}
				} else {
					return nil, fmt.Errorf("expected \n, found %c", char)
				}

			case parseKey:
				switch char {
				case '\r':
					s = expectLF

					if len(fields["content-length"]) > 0 {
						if strings.Contains(fields["content-type"], "json") || fields["content-type"] == "*/*" {
							nextState = parseBodyJSON
							continue StateMachineLoop
						} else if strings.Contains(fields["content-type"], "image") {
							nextState = parseBodyImageBin
							continue StateMachineLoop
						}
					}

					nextState = end

				case ':':
					key = string(readBuffer)
					readBuffer = []byte{}
					s = expectSpace
					nextState = parseValue

				default:
					readBuffer = append(readBuffer, char)
				}

			case expectSpace:
				if char == ' ' {
					s = nextState
				} else {
					return nil, fmt.Errorf("expected [space], found %c", char)
				}

			case parseValue:
				if char == '\r' {
					// header name is case-insensitive
					fields[strings.ToLower(key)] = strings.TrimSpace(string(readBuffer)) //trim optional leading and trailing whitespace
					readBuffer = []byte{}
					s = expectLF
					nextState = parseKey //state after the next state
				} else {
					readBuffer = append(readBuffer, char)
				}
			case parseBodyJSON:
				jsonStr = append(jsonStr, char)
				switch char {
				case '{':
					count += 1
				case '}':
					count -= 1
					if count == 0 {
						jsonObj := map[string]any{}
						if err := json.Unmarshal(jsonStr, &jsonObj); err != nil {
							_, _ = fmt.Printf("error while parsing json. Error: %s", err)
							return nil, err
						}
						request.Body = jsonObj
						break OuterLoop
					}
				}
			case parseBodyImageBin:
				imageBody = append(imageBody, char)
				bodyRead += 1
				contentLength, err := strconv.Atoi(fields["content-length"])
				if err != nil {
					return nil, err
				}

				if bodyRead >= contentLength {
					err := os.MkdirAll(UploadImagesFolder, os.ModePerm)
					if err != nil {
						return nil, err
					}

					fileUniqueName, err := generateHexKey(FileNameLength)
					if err != nil {
						return nil, err
					}
					contentType := fields["content-type"]
					_, extension, found := strings.Cut(contentType, "/")

					if !found {
						return nil, fmt.Errorf("the content-type is in wrong format")
					}

					filePath := UploadImagesFolder + "/" + "file" + fileUniqueName + "." + extension
					fmt.Printf("file name is: %s\n", filePath)

					err = os.WriteFile(filePath, []byte(imageBody), 0644)

					if err != nil {
						return nil, err
					}
					break OuterLoop
				}

			}
		}
	}
	return request, nil
}

// copy from gemini
func generateHexKey(length int) (string, error) {
	// Create a byte slice of the desired length
	bytes := make([]byte, length)

	// Fill the slice with cryptographically secure random bytes
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Hex encoding doubles the length (e.g., 16 bytes becomes a 32-character string)
	return hex.EncodeToString(bytes), nil
}
