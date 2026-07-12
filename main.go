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

type STATE int

const (
	parseMethod STATE = iota
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

type FRAMESTATE int

const (
	parseFin FRAMESTATE = iota
	parseOpCode
	parseMask
	parseLength
	parseLength16
	parseLength64
	parseFrameKey
	parsePayload
	endFrame
)

const UploadImagesFolder = "upload_images"
const FileNameLength = 8
const HOST = "localhost:8080"

func main() {
	fmt.Println("Hello, World!")
	fmt.Printf("Server listen on: %s\n", HOST)
	server, _ := net.Listen("tcp", HOST)

	for {
		connection, err := server.Accept()
		if err != nil {
			_, _ = fmt.Printf("can't open file, err: %s", err)
			return
		}

		go handleClient(connection)

	}
}

func createWebSocketOKResponse(base64Encode string) []byte {
	// Double quotes allow \r\n escape characters.
	// Note the double \r\n\r\n at the very end to signal the end of HTTP headers.
	result := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"Sec-WebSocket-Protocol: chat\r\n\r\n",
		base64Encode,
	)
	return []byte(result)
}

func createServerErrorResponse(err error) []byte {
	// It is safer to generate the JSON body first, then calculate its exact length dynamically.
	body := fmt.Sprintf(`{"error": "InternalServerError", "message": "%s"}`, err.Error())

	result := fmt.Sprintf(
		"HTTP/1.1 500 Internal Server Error\r\n"+
			"Date: Fri, 10 Jul 2026 01:07:00 GMT\r\n"+
			"Content-Type: application/json; charset=UTF-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n"+
			"%s",
		len(body), body,
	)
	return []byte(result)
}

func createBadRequestResponse(err error) []byte {
	body := fmt.Sprintf(`{"error": "unauthorized", "message": "%s"}`, err.Error())

	result := fmt.Sprintf(
		"HTTP/1.1 401 Unauthorized\r\n"+
			"Date: Sun, 12 Jul 2026 00:09:00 GMT\r\n"+
			"Content-Type: application/json; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"WWW-Authenticate: Bearer realm=\"://example.com\", error=\"invalid_token\"\r\n\r\n"+
			"%s",
		len(body), body,
	)
	return []byte(result)
}

func createOKResponse() []byte {
	body := `{"status": "success", "message": "hello"}`

	result := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n\r\n"+
			"%s",
		len(body), body,
	)
	return []byte(result)
}

func handleClient(con net.Conn) {
	contents, err := parseHTTPWithFTM(con)
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

func handleUpgradeConnection(request Request, con net.Conn) error {
	upgrade, ok := request.Header["upgrade"]
	if !ok {
		return fmt.Errorf("need to specify the upgrade protocol name")
	}
	if upgrade == "websocket" {
		code, err := handleWebsocketCon(request, con)
		if err != nil {
			errorResponse := []byte{}
			fmt.Println(string(errorResponse))
			if code == 401 {
				errorResponse = createBadRequestResponse(err)
			} else {
				errorResponse = createServerErrorResponse(err)
			}
			_, err = con.Write(errorResponse)
			if err != nil {
				_, _ = fmt.Printf("can't send response, err: %s", err)
				return err
			}
		}

		if code == 200 {
			fmt.Println("Send close signal")
			// fin and opcode
			closeByte := 0b10001000

			data := []byte("goodbye\n")

			statusCode := uint16(1000)
			statusCodeBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(statusCodeBytes, statusCode)

			payload := []byte{}
			payload = append(payload, statusCodeBytes...)
			payload = append(payload, data...)

			lengthandMask := byte(len(payload))

			closeResponse := []byte{byte(closeByte), byte(lengthandMask)}
			closeResponse = append(closeResponse, payload...)

			con.Write([]byte(closeResponse))
		}
	} else {
		return fmt.Errorf("upgrade protocol not allowed: %s", upgrade)
	}
	return nil
}

func handleWebsocketCon(request Request, con net.Conn) (int, error) {
	method := request.RequestLine.Method
	if method != "GET" {
		return 401, fmt.Errorf("method not allowed for websocket: %s, expedted GET", method)
	}
	header := request.Header
	host, ok := header["host"]
	if !ok {
		return 401, fmt.Errorf("missing header, expected host")
	}
	secWebSocketKey, ok := header["sec-websocket-key"]
	if !ok {
		return 401, fmt.Errorf("missing header, expected sec-websocket-key")
	}
	secWebSocketVersion, ok := header["sec-websocket-version"]
	if !ok {
		return 401, fmt.Errorf("missing header, expected sec-websocket-version")
	}

	if host != HOST {
		return 401, fmt.Errorf("connect to wrong host")
	}

	if !isValidBase64([]byte(secWebSocketKey)) {
		return 401, fmt.Errorf("websocket key is not a valid base64")
	}

	if secWebSocketVersion != "13" {
		return 401, fmt.Errorf("websocket version is not supported")
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
			return 500, err
		}

		fmt.Printf("frame is %+v", frame)
		if frame.OpCode == 0x08 {
			fmt.Println("close connection now")
			break
		}
	}

	return 200, nil
}

func parseWebsocketFrame(con net.Conn) (WebsocketFrame, error) {
	fmt.Println("Start parsing websocketframe")
	endParsing := false
	frame := WebsocketFrame{}
	readBuffer := make([]byte, 1024)
	s := parseFin
	var cumLength uint64 = 0
	count := 0
	maskKey := [4]byte{}
	keyCount := 0
	rest := 0
	cumPayload := []byte{}

ReadBufferLoop:
	for !endParsing {
		fmt.Println("read once?")
		bytes, err := con.Read(readBuffer)
		if err != nil {
			return WebsocketFrame{}, err
		}
		fmt.Printf("read %d\n", bytes)

		i := 0
		for i < bytes {
			char := readBuffer[i]
			fmt.Printf("State: %d\n", s)
			fmt.Printf("parsing: %b\n", char)
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
				if opcode == 0x08 {
					return frame, nil
				}

			case parseMask:
				mask := char >> 7
				frame.IsMask = (mask == 0x01)
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

func parseHTTPWithFTM(con net.Conn) (Request, error) {
	fmt.Println("parsing nowwww")
	s := parseMethod
	var nextState STATE
	buffer := make([]uint8, 1024)
	request := Request{}
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
			return Request{}, err
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
					return Request{}, fmt.Errorf("expected \n, found %c", char)
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
					return Request{}, fmt.Errorf("expected [space], found %c", char)
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
							return Request{}, err
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
					return Request{}, err
				}

				if bodyRead >= contentLength {
					err := os.MkdirAll(UploadImagesFolder, os.ModePerm)
					if err != nil {
						return Request{}, err
					}

					fileUniqueName, err := generateHexKey(FileNameLength)
					if err != nil {
						return Request{}, err
					}
					contentType := fields["content-type"]
					_, extension, found := strings.Cut(contentType, "/")

					if !found {
						return Request{}, fmt.Errorf("the content-type is in wrong format")
					}

					filePath := UploadImagesFolder + "/" + "file" + fileUniqueName + "." + extension
					fmt.Printf("file name is: %s\n", filePath)

					err = os.WriteFile(filePath, []byte(imageBody), 0644)

					if err != nil {
						return Request{}, err
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
