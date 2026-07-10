package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func handleClient(con net.Conn) {
	contents, err := parseHTTPWithFTM(con)
	if err != nil {
		errorResponse := fmt.Sprintf(`HTTP/1.1 500 Internal Server Error
Date: Fri, 10 Jul 2026 01:07:00 GMT
Content-Type: application/json; charset=UTF-8
Content-Length: %d
Connection: close

{
  "error": "InternalServerError",
  "message": "%s"
}
`, 53+len(err.Error()), err)
		_, err = con.Write([]byte(errorResponse))
		if err != nil {
			_, _ = fmt.Printf("can't send response, err: %s", err)
			return
		}
	}
	response := `HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 41

{"status": "success", "message": "hello"}`
	_, err = con.Write([]byte(response))
	if err != nil {
		_, _ = fmt.Printf("can't send response, err: %s", err)
		return
	}

	fmt.Printf("Request: %#v\n", contents)

	allowedMethod := []string{"GET", "POST"}
	method := contents.RequestLine.Method

	if !slices.Contains(allowedMethod, method) {
		_, _ = fmt.Printf("method %s not allowed", method)
		return
	}

	fmt.Printf("body is: %v\n", contents.Body)
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

					if len(fields["Content-Length"]) > 0 {
						if strings.Contains(fields["Content-Type"], "json") || fields["Content-Type"] == "*/*" {
							nextState = parseBodyJSON
							continue StateMachineLoop
						} else if strings.Contains(fields["Content-Type"], "image") {
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
					fields[key] = strings.TrimSpace(string(readBuffer)) //trim optional leading and trailing whitespace
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
				contentLength, err := strconv.Atoi(fields["Content-Length"])
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
					contentType := fields["Content-Type"]
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

func parseHTTP(con net.Conn) (map[string]any, error) {
	fmt.Println("parsing nowwww")
	buffer := make([]uint8, 1000)
	result := map[string]any{}
	for {
		bytes, err := con.Read(buffer)
		if bytes <= 0 {
			break
		}
		if err != nil {
			_, _ = fmt.Printf("can't read file, err: %s", err)
			return nil, nil
		}

		// split header and body
		head, body, found := strings.Cut(string(buffer[:bytes]), "\r\n\r\n")
		if !found {
			return map[string]any{}, errors.New("unproper protocol message")
		}

		startLine, header, found := strings.Cut(head, "\r\n")
		if !found {
			return map[string]any{}, errors.New("unproper protocol message")
		}

		//parse startline
		keyFields := strings.Split(startLine, " ")
		method := keyFields[0]
		result["Method"] = method
		route := keyFields[1]
		result["Route"] = route
		version := keyFields[2]
		result["Version"] = version

		//parse header
		for value := range strings.SplitSeq(header, "\r\n") {
			fields := strings.Split(value, ": ")
			fieldKey := fields[0]
			fieldValue := strings.Join(fields[1:], " ")
			result[fieldKey] = fieldValue
		}

		//parse body
		contentLength := result["Content-Length"]
		if contentLength != nil {
			bodyMap := map[string]any{}
			if err := json.Unmarshal([]byte(body), &bodyMap); err != nil {
				_, _ = fmt.Printf("error while parsing json. Error: %s", err)
				return nil, nil
			}
			result["Body"] = bodyMap
		} else {
			fmt.Println("endparsing-------")
			return result, nil
		}

	}
	fmt.Println("endparsing-------")
	return result, nil
}
