package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
)

type STATE int

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

const UploadImagesFolder = "upload_images"
const FileNameLength = 8

func main() {
	fmt.Println("Hello, World!")
	const ADDR = "localhost:8080"
	fmt.Printf("Server listen on: %s\n", ADDR)
	server, _ := net.Listen("tcp", ADDR)

	for {
		connection, err := server.Accept()
		if err != nil {
			_, _ = fmt.Printf("can't open file, err: %s", err)
			return
		}

		go handleClient(connection)

	}
}

func createServerErrorRepsponse(err error) []byte {
	result := fmt.Sprintf(`HTTP/1.1 500 Internal Server Error
Date: Fri, 10 Jul 2026 01:07:00 GMT
Content-Type: application/json; charset=UTF-8
Content-Length: %d
Connection: close

{
  "error": "InternalServerError",
  "message": "%s"
}
`, 53+len(err.Error()), err)
	return []byte(result)
}

func createOKResponse() []byte {
	return []byte(`HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 41

{"status": "success", "message": "hello"}`)
}

func handleClient(con net.Conn) {
	contents, err := parseHTTPWithFTM(con)
	if err != nil {
		errorResponse := createServerErrorRepsponse(err)
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
		return
	}

	fmt.Printf("body is: %v\n", contents.Body)

	err = handleWebsocketCon(contents)
	if err != nil {
		errorResponse := createServerErrorRepsponse(err)
		_, err = con.Write(errorResponse)
		if err != nil {
			_, _ = fmt.Printf("can't send response, err: %s", err)
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

func handleWebsocketCon(request Request) error {
	method := request.RequestLine.Method
	if method != "GET" {
		return fmt.Errorf("method not allowed for websocket: %s, expedted GET", method)
	}
	return nil
}

func parseHTTPWithFTM(con net.Conn) (Request, error) {
	fmt.Println("parsing nowwww")
	s := parseMethod
	var nextState STATE
	buffer := make([]uint8, 8)
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
