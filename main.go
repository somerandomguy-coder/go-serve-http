package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RequestLine struct {
	Method        string
	RequestTarget string
	HTTPVersion   string
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

type SecureConn struct {
	conn             net.Conn
	isSecure         bool
	ServerPrivateKey *ecdh.PrivateKey
	sharedSecretKey  []byte
	transcript       []byte
	clientKey        []byte
	clientIV         []byte
	incomingSeq      uint64
	serverKey        []byte
	serverIV         []byte
	outgoing         uint64

	// Handshake Secrets
	serverHandshakeKey []byte
	serverHandshakeIV  []byte
	handshakeSeq       uint64

	handshakeSecret   []byte
	serverFinishedKey []byte

	clientHandshakeKey []byte
	clientHandshakeIV  []byte

	clientFinishedKey []byte
}

// wrapper around the Net.conn behavior

func (s *SecureConn) Read(b []byte) (int, error) {
	if s.isSecure {
		// incrementally read the message
		headerBuf := make([]byte, 5)
		byteRead, err := s.conn.Read(headerBuf)
		if err != nil {
			// if err.Error() == "EOF" {
			// 	fmt.Println("Client disconnected cleanly (EOF)")
			// 	return byteRead, nil
			// }
			fmt.Printf("error while reading from connection %s", err)
			return 0, err
		}
		header := headerBuf[:byteRead]

		tag := header[0]

		//check if header is
		if tag != ApplicationData {
			return 0, fmt.Errorf("record header incorrect format, this is not ApplicationData")
		}

		payloadLenBuf := header[3:5] //the last 2 bytes of header contains the length
		payloadLen := int(binary.BigEndian.Uint16(payloadLenBuf))

		payloadBuf := make([]byte, payloadLen)

		byteRead, err = s.conn.Read(payloadBuf)
		if err != nil {
			// if err.Error() == "EOF" {
			// 	fmt.Println("Client disconnected cleanly (EOF)")
			// 	return byteRead, nil
			// }
			fmt.Printf("error while reading from connection %s", err)
			return 0, err
		}
		ciphertext := payloadBuf[:byteRead]

		fmt.Printf("read this much bytes from pipe: %d\n", byteRead)
		fmt.Printf("INFO: header is: %v\n", header)

		fmt.Printf("INFO: ciphertext is: %v\n", ciphertext)
		result, err := DecryptRecord(ciphertext, header, s.clientKey, s.clientIV, s.incomingSeq)
		fmt.Printf("decrypted msg: %v\n", result)
		if err != nil {
			return 0, err
		}
		tag = result[len(result)-1]
		if tag != ApplicationData {
			return 0, fmt.Errorf("payload incorrect format, this is not ApplicationData")
		}

		cleanPayload := result[:len(result)-1]

		fmt.Printf("decrypted msg: %q\n", cleanPayload)
		if len(cleanPayload) > len(b) {
			_ = fmt.Errorf("buffer too smol, need bigger buffer")
		}
		byteCopy := copy(b, cleanPayload)
		s.incomingSeq += 1

		return byteCopy, nil
	} else {
		return s.conn.Read(b) //not secure connection read
	}
}

func (s *SecureConn) Write(b []byte) (int, error) {
	if s.isSecure {
		result, err := secure(s, &b)
		if err != nil {
			return 0, err
		}
		s.outgoing += 1
		return s.conn.Write(*result)
	} else {
		return s.conn.Write(b)
	}
}

func secure(con *SecureConn, message *[]byte) (*[]byte, error) {
	result := *message
	// append record at the front and back

	result = append(result, 0x17) // denote that the message is over

	//TODO: fix this later
	// 2. Pre-calculate the GCM Ciphertext Length (Plaintext + 16-byte GCM tag)
	ciphertextLen := len(result) + 16

	fmt.Printf("unencryptedData is: %v\n", result)

	aad := make([]byte, 5)
	aad[0] = ApplicationData // 0x17
	aad[1] = 0x03            // Legacy Version High
	aad[2] = 0x03            // Legacy Version Low
	binary.BigEndian.PutUint16(aad[3:5], uint16(ciphertextLen))

	encryptedMessage, err := EncryptRecord(result, aad, con.serverKey, con.serverIV, con.outgoing)
	if err != nil {
		return nil, err
	}

	payloadLen := len(encryptedMessage)

	recordHeaderLen := 5 // 0x17, 0x03, 0x01 + 2 bytes length
	totalLength := recordHeaderLen + payloadLen

	// allocate enough memory
	result = make([]byte, 0, totalLength)

	// record header
	result = append(result, ApplicationData, 0x03, 0x03) // type and version 3 bytes
	recordLenBytes := [2]byte{}
	binary.BigEndian.PutUint16(recordLenBytes[:], uint16(payloadLen))
	result = append(result, recordLenBytes[:]...) // length 2 bytes

	// payload
	result = append(result, encryptedMessage...)

	fmt.Printf("final data is: %v\n", result)
	fmt.Printf("final data len is: %d\n", len(result))

	return &result, nil
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

const (
	Handshake       byte = 0x16
	ApplicationData byte = 0x17
)

type RecordHeader struct {
	contentType   byte
	legacyVersion [2]byte
	length        int
}

const (
	TLSClientHello         byte = 0x01
	TLSServerHello         byte = 0x02
	TLSEncryptedExtensions byte = 0x08
	TLSCertificate         byte = 0xb
	TLSCertificateVerify   byte = 0xf
	TLSFinished            byte = 0x14
)

type HandshakeHeader struct {
	handshakeType byte
	length        int
}

type HelloPayload struct {
	legacyVersion            [2]byte /* TLS v1.2 */
	random                   [32]byte
	legacySessionID          []byte
	cipherSuites             []byte
	legacyCompressionMethods []byte
	extensions               []byte
}

type TLSMessage struct {
	recordHeader     RecordHeader    // 5 bytes
	handshakeHeader  HandshakeHeader // 4 bytes
	HelloPayload     HelloPayload
	EncryptedPayload []byte
}

// Create a global pool for 1024-byte buffers
var bufferPool = sync.Pool{
	New: func() any {
		// This runs only when the pool is completely empty
		b := make([]byte, 2048)
		return &b // Return a pointer to avoid copying the slice header
	},
}

const UploadImagesFolder = "upload_images"
const FileNameLength = 8
const Host = "localhost:8080"
const IsSecure = true

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
			fmt.Printf("can't accept connection, err: %s", err)
			// if err just continue
			continue
		}

		//wrap around by a secure connection
		secureConnection := SecureConn{
			conn:     connection,
			isSecure: IsSecure}

		if secureConnection.isSecure {
			//initiate the transcript
			err := handshake(&secureConnection)
			if err != nil {
				fmt.Printf("failed to perform handshake, err: %s", err)
				continue
			}
			fmt.Println("succesfully establish secure connection!!!")
		}

		go handleClient(&secureConnection)
	}
}

func handshake(con *SecureConn) error {
	publicKey, _ := generateX25519KeyShare(con)
	message, err := readClientHello(con)
	if err != nil {
		return err
	}
	serverHelloResponse := createDynamicServerHello(con, &message, &publicKey)
	_, err = con.conn.Write(*serverHelloResponse)
	if err != nil {
		fmt.Println("eROREeroer")
		return err
	}

	DeriveHandshakeTrafficKeys(con)

	encryptedExtension, err := createEncryptedExtension(con)
	if err != nil {
		return err
	}
	con.conn.Write(*encryptedExtension)

	certificate, err := createCertificate(con)
	if err != nil {
		return err
	}
	con.conn.Write(*certificate)

	certificateVerify, err := createCertificateVerify(con)
	if err != nil {
		return err
	}
	con.conn.Write(*certificateVerify)

	serverFinish, err := createServerFinish(con)
	if err != nil {
		return err
	}
	con.conn.Write(*serverFinish)

	err = readClientFinish(con)
	if err != nil {
		return err
	}

	return nil
}

// sorry, too much stuff so i let gemini generate this too

func readClientFinish(con *SecureConn) error {
	// 1. Read the 5-byte TLS record header
	var header []byte

	for {
		header = make([]byte, 5)
		if _, err := io.ReadFull(con.conn, header); err != nil {
			return fmt.Errorf("failed to read client finish record header: %w", err)
		}

		// 1. If we hit a Middlebox Compatibility dummy record (0x14), consume and discard it
		if header[0] == 0x14 {
			ccsLen := binary.BigEndian.Uint16(header[3:5])
			dummyPayload := make([]byte, ccsLen)
			if _, err := io.ReadFull(con.conn, dummyPayload); err != nil {
				return fmt.Errorf("failed to consume dummy CCS payload: %w", err)
			}
			// Loop back to read the actual encrypted Finished record immediately following it
			continue
		}

		break
	}

	if header[0] != ApplicationData {
		return fmt.Errorf("expected encrypted application data record (0x17), got: 0x%x", header[0])
	}

	// 2. Read the ciphertext payload
	ciphertextLen := binary.BigEndian.Uint16(header[3:5])
	ciphertext := make([]byte, ciphertextLen)
	if _, err := io.ReadFull(con.conn, ciphertext); err != nil {
		return fmt.Errorf("failed to read client finish ciphertext: %w", err)
	}

	// 3. Decrypt the payload using the Client Handshake keys (Sequence 0)
	plaintext, err := DecryptRecord(ciphertext, header, con.clientHandshakeKey, con.clientHandshakeIV, 0)
	if err != nil {
		return fmt.Errorf("failed decrypting client finished record: %w", err)
	}

	if len(plaintext) == 0 {
		return fmt.Errorf("decrypted client finish payload is empty")
	}

	// 4. Verify and strip the trailing inner content type byte
	innerType := plaintext[len(plaintext)-1]
	if innerType != Handshake {
		return fmt.Errorf("expected inner content type 0x16 (Handshake), got: 0x%x", innerType)
	}

	// ... [Inside readClientFinish, right after verifying innerType == Handshake] ...
	clientFinishPayload := plaintext[:len(plaintext)-1]

	// 1. Check the Handshake header type inside the decrypted payload
	if clientFinishPayload[0] != TLSFinished { // 0x14
		return fmt.Errorf("expected client finished type 0x14, got 0x%x", clientFinishPayload[0])
	}

	// 2. Extract the client's verify_data tag (skip 1 byte type + 3 bytes length header)
	clientVerifyData := clientFinishPayload[4:]

	// 3. Compute your expected HMAC over the transcript *up to* the Server Finished message
	currentTranscriptHash := sha256.Sum256(con.transcript)
	h := hmac.New(sha256.New, con.clientFinishedKey)
	h.Write(currentTranscriptHash[:])
	expectedVerifyData := h.Sum(nil)

	// 4. Securely compare both verification tags
	if !hmac.Equal(clientVerifyData, expectedVerifyData) {
		return fmt.Errorf("client finished verification failed: transcript mismatch")
	}

	// 5. If it passes, commit the unencrypted data to the running transcript
	con.transcript = append(con.transcript, clientFinishPayload...)

	// The application keys derived during createServerFinish are already
	// safely sitting inside con.clientKey and con.serverKey, untouched and ready.
	return nil
}

//copy when debug

func DeriveHandshakeTrafficKeys(con *SecureConn) {
	zeroSalt := make([]byte, sha256.Size)
	zeroIKM := make([]byte, sha256.Size)
	emptyHash := sha256.Sum256([]byte(""))

	earlySecret := hkdfExtract(zeroSalt, zeroIKM)
	derivedSecret := hkdfExpandLabel(earlySecret, "derived", emptyHash[:], sha256.Size)

	// 1. Save the actual Handshake Secret to the connection state
	con.handshakeSecret = hkdfExtract(derivedSecret, con.sharedSecretKey)

	transcriptHash := sha256.Sum256(con.transcript) // Strictly CH + SH here

	serverHandshakeTrafficSecret := hkdfExpandLabel(
		con.handshakeSecret,
		"s hs traffic",
		transcriptHash[:],
		sha256.Size,
	)

	con.serverHandshakeKey = hkdfExpandLabel(serverHandshakeTrafficSecret, "key", []byte(""), 16)
	con.serverHandshakeIV = hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", []byte(""), 12)

	// 2. Derive and save the permanent Finished Key
	con.serverFinishedKey = hkdfExpandLabel(serverHandshakeTrafficSecret, "finished", []byte(""), sha256.Size)
	con.handshakeSeq = 0

	clientHandshakeTrafficSecret := hkdfExpandLabel(con.handshakeSecret, "c hs traffic", transcriptHash[:], sha256.Size)
	con.clientHandshakeKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "key", []byte(""), 16)
	con.clientHandshakeIV = hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", []byte(""), 12)

	// Add this line to compute the client's verification key:
	con.clientFinishedKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "finished", []byte(""), sha256.Size)
}

//copy from gemini

func EncryptRecord(plaintext []byte, aad []byte, serverKey []byte, baseIV []byte, seqNum uint64) ([]byte, error) {
	block, err := aes.NewCipher(serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, len(baseIV))
	copy(nonce, baseIV)

	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seqNum)

	for i := range 8 {
		nonce[4+i] ^= seqBytes[i]
	}

	// Pass the 5-byte record header as the final AAD argument here
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, aad)

	return ciphertext, nil
}

// DecryptRecord decrypts an incoming application message using AES-GCM and a sequence number.

func DecryptRecord(ciphertext []byte, aad []byte, clientKey []byte, baseIV []byte, seqNum uint64) ([]byte, error) {
	block, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, len(baseIV))
	copy(nonce, baseIV)

	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seqNum)

	for i := range 8 {
		nonce[4+i] ^= seqBytes[i]
	}

	// Pass the intercepted 5-byte header slice as AAD to unlock the box
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// copy from gemini

func DeriveApplicationKeysRaw(handshakeSecret []byte, finalTranscriptHash []byte, keyLen int, ivLen int) (clientKey, clientIV, serverKey, serverIV []byte) {
	hashSize := sha256.Size // 32 bytes for SHA-256
	zeroIKM := make([]byte, hashSize)

	sum := sha256.Sum256([]byte(""))
	// 1. Transition from Handshake Secret to Master Secret
	derivedSecret := hkdfExpandLabel(handshakeSecret, "derived", sum[:], hashSize)
	masterSecret := hkdfExtract(derivedSecret, zeroIKM)

	// 2. Derive Application Traffic Secrets
	clientAppSecret := hkdfExpandLabel(masterSecret, "c ap traffic", finalTranscriptHash, hashSize)
	serverAppSecret := hkdfExpandLabel(masterSecret, "s ap traffic", finalTranscriptHash, hashSize)

	// 3. Generate symmetric Keys and IVs directly into the return variables
	clientKey = hkdfExpandLabel(clientAppSecret, "key", []byte(""), keyLen)
	clientIV = hkdfExpandLabel(clientAppSecret, "iv", []byte(""), ivLen)

	serverKey = hkdfExpandLabel(serverAppSecret, "key", []byte(""), keyLen)
	serverIV = hkdfExpandLabel(serverAppSecret, "iv", []byte(""), ivLen)

	return clientKey, clientIV, serverKey, serverIV
}

// copy from gemini
func generateX25519KeyShare(con *SecureConn) ([]byte, error) {
	// 1. Select the Curve (X25519)
	curve := ecdh.X25519()

	// 2. Generate the Private Key using crypto/rand
	// Go automatically handles the X25519 scalar clamping/pruning under the hood
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Save the private key to your connection state machine
	con.ServerPrivateKey = privateKey

	// 3. Deriving the Public Key Object
	publicKey := privateKey.PublicKey()

	// 4. Exporting the Raw Bytes
	// This returns the exact 32 bytes needed for the Key Share extension
	rawPublicKeyBytes := publicKey.Bytes()

	return rawPublicKeyBytes, nil
}

// another function being copied from gemini

func ExpandLabel(secret []byte, label string, context []byte, length uint16) ([]byte, error) {
	// 1. Construct the HkdfLabel structure
	// struct {
	//     uint16 length = Length;
	//     opaque label<7..255> = "tls13 " + Label;
	//     opaque context<0..255> = Context;
	// } HkdfLabel;

	fullLabel := "tls13 " + label
	labelLen := len(fullLabel)

	// Calculate total size: 2 bytes (length) + 1 byte (label size) + label string + 1 byte (context size) + context data
	hkdfLabel := make([]byte, 2, 2+1+labelLen+1+len(context))

	// Put 16-bit big-endian length
	binary.BigEndian.PutUint16(hkdfLabel, length)

	// Put label with length prefix
	hkdfLabel = append(hkdfLabel, byte(labelLen))
	hkdfLabel = append(hkdfLabel, []byte(fullLabel)...)

	// Put context with length prefix
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	// 2. Perform HKDF-Expand (using HMAC-SHA256 in this example)
	// For standard HKDF, this requires iterating if length > Hash.Size()
	h := hmac.New(sha256.New, secret)
	h.Write(hkdfLabel)
	h.Write([]byte{0x01}) // HKDF-Expand uses a single iteration (T(1)) for lengths <= Hash.Size()

	return h.Sum(nil)[:length], nil
}

//These 3 function took straight from gemini

// HKDF-Extract as defined in RFC 5869
func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size) // defaults to all zeros
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// HKDF-Expand-Label structures the label as required by TLS 1.3 (RFC 8446 Sec 7.1)
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	// TLS 1.3 wraps labels in a specific "tls13 " prefix
	tls13Label := "tls13 " + label

	// Create the HkdfLabel structure layout:
	// 2 bytes: length
	// 1 byte:  length of ("tls13 " + label)
	// N bytes: "tls13 " + label
	// 1 byte:  length of context
	// M bytes: context
	hkdfLabel := make([]byte, 2+1+len(tls13Label)+1+len(context))

	binary.BigEndian.PutUint16(hkdfLabel[0:2], uint16(length))
	hkdfLabel[2] = byte(len(tls13Label))
	copy(hkdfLabel[3:], tls13Label)
	hkdfLabel[3+len(tls13Label)] = byte(len(context))
	copy(hkdfLabel[3+len(tls13Label)+1:], context)

	// Perform standard HKDF-Expand (RFC 5869)
	// For length <= 32 bytes (SHA-256), a single HMAC block iteration is enough:
	info := hkdfLabel
	info = append(info, 0x01) // Block constant counter

	h := hmac.New(sha256.New, secret)
	h.Write(info)
	okm := h.Sum(nil)

	return okm[:length]
}

func createServerFinish(con *SecureConn) (*[]byte, error) {
	recordHeaderLen := 5        // 0x17, 0x03, 0x01 + 2 bytes length
	initHandshakeHeaderLen := 4 // TLSType + 3 bytes length

	transcriptHash := sha256.Sum256(con.transcript)

	h := hmac.New(sha256.New, con.serverFinishedKey)
	h.Write(transcriptHash[:])
	verifyData := h.Sum(nil)
	finishLength := len(verifyData)

	// handshake header
	unencryptedData := make([]byte, 0, initHandshakeHeaderLen)
	unencryptedData = append(unencryptedData, TLSFinished) // 1 byte
	handshakeLenBytes := [4]byte{}
	binary.BigEndian.PutUint32(handshakeLenBytes[:], uint32(finishLength))
	unencryptedData = append(unencryptedData, handshakeLenBytes[1:]...) // lenght 3 bytes

	// handshake payload
	unencryptedData = append(unencryptedData, verifyData...) // verify data

	con.transcript = append(con.transcript, unencryptedData...)

	unencryptedData = append(unencryptedData, 0x16)

	ciphertextLen := len(unencryptedData) + 16

	aad := make([]byte, 5)
	aad[0] = ApplicationData // 0x17
	aad[1] = 0x03            // Legacy Version High
	aad[2] = 0x03            // Legacy Version Low
	binary.BigEndian.PutUint16(aad[3:5], uint16(ciphertextLen))

	encryptedData, err := EncryptRecord(unencryptedData, aad, con.serverHandshakeKey, con.serverHandshakeIV, con.handshakeSeq)
	if err != nil {
		return nil, err
	}

	encryptedDataLength := len(encryptedData)
	totalLength := recordHeaderLen + encryptedDataLength

	result := make([]byte, 0, totalLength)

	// record header
	result = append(result, ApplicationData, 0x03, 0x03) // type and version 3 bytes
	recordLenBytes := [2]byte{}
	binary.BigEndian.PutUint16(recordLenBytes[:], uint16(encryptedDataLength))
	result = append(result, recordLenBytes[:]...) // length 2 bytes

	result = append(result, encryptedData...) // should i copy mem instead?

	finalTranscriptHash := sha256.Sum256(con.transcript)
	cKey, cIV, sKey, sIV := DeriveApplicationKeysRaw(con.handshakeSecret, finalTranscriptHash[:], 16, 12)
	con.clientKey = cKey
	con.clientIV = cIV
	con.serverKey = sKey
	con.serverIV = sIV

	con.incomingSeq = 0
	con.outgoing = 0
	con.handshakeSeq += 1

	return &result, nil
}

func createCertificateVerify(con *SecureConn) (*[]byte, error) {
	// read the mkcert generated credential
	binaryData, err := LoadAndSignTranscript("./localhost-key.pem", sha256.Sum256(con.transcript))
	if err != nil {
		return nil, err
	}
	recordHeaderLen := 5        // 0x17, 0x03, 0x01 + 2 bytes length
	initHandshakeHeaderLen := 4 // TLSType + 3 bytes length

	// handshake header
	unencryptedData := make([]byte, 0, initHandshakeHeaderLen)
	unencryptedData = append(unencryptedData, TLSCertificateVerify) // 1 byte
	handshakeLenBytes := [4]byte{}

	signLength := len(binaryData)
	initPayloadLen := 2 + // signature algorithm
		2 + // signature length
		signLength // actual signature binary

	binary.BigEndian.PutUint32(handshakeLenBytes[:], uint32(initPayloadLen))
	unencryptedData = append(unencryptedData, handshakeLenBytes[1:]...) // lenght 3 bytes

	// handshake payload
	unencryptedData = append(unencryptedData, 0x08, 0x04) //signature algorithm rsa_pss_rsae_sha256
	signBuf := make([]byte, 2)
	// Cast int to uint32 and write to the 2-byte buffer
	binary.BigEndian.PutUint16(signBuf, uint16(signLength))
	unencryptedData = append(unencryptedData, signBuf...)    // signature length
	unencryptedData = append(unencryptedData, binaryData...) // actual binary of signature

	con.transcript = append(con.transcript, unencryptedData...)

	unencryptedData = append(unencryptedData, 0x16)

	ciphertextLen := len(unencryptedData) + 16

	aad := make([]byte, 5)
	aad[0] = ApplicationData // 0x17
	aad[1] = 0x03            // Legacy Version High
	aad[2] = 0x03            // Legacy Version Low
	binary.BigEndian.PutUint16(aad[3:5], uint16(ciphertextLen))

	encryptedData, err := EncryptRecord(unencryptedData, aad, con.serverHandshakeKey, con.serverHandshakeIV, con.handshakeSeq)
	if err != nil {
		return nil, err
	}

	encryptedDataLength := len(encryptedData)

	totalLength := recordHeaderLen + encryptedDataLength

	result := make([]byte, 0, totalLength)

	// record header
	result = append(result, ApplicationData, 0x03, 0x03) // type and version 3 bytes
	recordLenBytes := [2]byte{}
	binary.BigEndian.PutUint16(recordLenBytes[:], uint16(encryptedDataLength))
	result = append(result, recordLenBytes[:]...) // length 2 bytes

	result = append(result, encryptedData...) // should i copy mem instead?

	// increase outbound message
	con.handshakeSeq += 1

	return &result, nil
}

//copy completely from gemini, i don't want to deal with this sh

func LoadAndSignTranscript(pemFilePath string, transcriptHash [32]byte) ([]byte, error) {
	// 1. Load the localhost-key.pem file
	pemBytes, err := os.ReadFile(pemFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// 2. Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil || (block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY") {
		return nil, fmt.Errorf("failed to decode valid PEM block from private key")
	}

	// 3. Parse into an RSA Private Key object
	var rsaKey *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		// Handles PKCS#8 formatting (which modern mkcert files use)
		var parsedKey any
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			rsaKey, ok = parsedKey.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("parsed PKCS#8 key is not an RSA private key")
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	// 4. Build the 64-space padding + context string + transcript hash buffer
	contextStr := "TLS 1.3, server CertificateVerify"
	totalBufferLen := 64 + len(contextStr) + 1 + len(transcriptHash)
	signBuffer := make([]byte, 0, totalBufferLen)

	// Append 64 space bytes (0x20)
	for range 64 {
		signBuffer = append(signBuffer, 0x20)
	}

	// Append context string and the required 0x00 null byte delimiter
	signBuffer = append(signBuffer, contextStr...)
	signBuffer = append(signBuffer, 0x00)

	// Append the 32-byte Handshake Transcript Hash
	signBuffer = append(signBuffer, transcriptHash[:]...)

	// 5. Hash the combined buffer with SHA-256
	hashedBuffer := sha256.Sum256(signBuffer)

	// 6. Sign using RSA-PSS (Required for TLS 1.3 RSA suites instead of PKCS1v15)
	// Passing crypto.SHA256 tells Go to internally check the digest configuration
	signature, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, hashedBuffer[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		return nil, fmt.Errorf("rsa-pss signing failed: %w", err)
	}

	return signature, nil
}

func createCertificate(con *SecureConn) (*[]byte, error) {
	// read the mkcert generated credential
	b64String, err := os.ReadFile("./localhost.pem")
	if err != nil {
		return nil, err
	}
	split := strings.Split(string(b64String), "\n")
	split = split[1 : len(split)-2]
	b64 := strings.Join(split, "")
	binaryData, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		log.Fatalf("Decoding failed 2: %v", err)
	}
	certLength := len(binaryData)

	recordHeaderLen := 5 // 0x16, 0x03, 0x01 + 2 bytes length
	initialHandshakeHeaderLen := 4
	initPayloadLen := 1 + // context len
		3 + // certs total length
		3 + // cert length
		certLength + // actual certificate
		2 // extension length

	// handshake header
	unencryptedData := make([]byte, 0, initialHandshakeHeaderLen)
	unencryptedData = append(unencryptedData, TLSCertificate) // 1 byte
	handshakeLenBytes := [4]byte{}
	binary.BigEndian.PutUint32(handshakeLenBytes[:], uint32(initPayloadLen))
	unencryptedData = append(unencryptedData, handshakeLenBytes[1:]...) // lenght 3 bytes

	// handshake payload
	unencryptedData = append(unencryptedData, 0x00) // certificate request context len

	certTotalBuf := make([]byte, 4)
	// Cast int to uint32 and write to the 4-byte buffer
	binary.BigEndian.PutUint32(certTotalBuf, uint32(certLength+5))
	unencryptedData = append(unencryptedData, certTotalBuf[1:]...) // certificate total length = certLength + 3 byte for len + 2 for extensions

	certBuf := make([]byte, 4)
	// Cast int to uint32 and write to the 4-byte buffer
	binary.BigEndian.PutUint32(certBuf, uint32(certLength))
	unencryptedData = append(unencryptedData, certBuf[1:]...) // certificate length of one cert
	unencryptedData = append(unencryptedData, binaryData...)  // actual binary of certificate
	unencryptedData = append(unencryptedData, 0x00, 0x00)     // extension length

	// save the unencrypted to the transcript
	con.transcript = append(con.transcript, unencryptedData...)

	unencryptedData = append(unencryptedData, 0x16) //denote the end of encrypted data

	ciphertextLen := len(unencryptedData) + 16

	aad := make([]byte, 5)
	aad[0] = ApplicationData // 0x17
	aad[1] = 0x03            // Legacy Version High
	aad[2] = 0x03            // Legacy Version Low
	binary.BigEndian.PutUint16(aad[3:5], uint16(ciphertextLen))

	encryptedData, err := EncryptRecord(unencryptedData, aad, con.serverHandshakeKey, con.serverHandshakeIV, con.handshakeSeq)
	if err != nil {
		return nil, err
	}

	payloadLen := len(encryptedData)

	//TODO: move from here
	totalLength := recordHeaderLen + payloadLen

	result := make([]byte, 0, totalLength)

	// record header
	result = append(result, ApplicationData, 0x03, 0x03) // type and version 3 bytes
	recordLenBytes := [2]byte{}
	binary.BigEndian.PutUint16(recordLenBytes[:], uint16(payloadLen))
	result = append(result, recordLenBytes[:]...) // length 2 bytes

	result = append(result, encryptedData...) // should i copy mem instead?

	// increase outgoing counter
	con.handshakeSeq += 1

	return &result, nil
}

func createEncryptedExtension(con *SecureConn) (*[]byte, error) {
	recordHeaderLen := 5 // 0x17, 0x03, 0x01 + 2 bytes length
	// handshake header
	initialHandshakeHeaderLen := 4 + 2 + 1 // header + payload + 0x16 to end the handshake

	unencryptedData := make([]byte, 0, initialHandshakeHeaderLen)
	unencryptedData = append(unencryptedData, TLSEncryptedExtensions) // 1 byte
	unencryptedData = append(unencryptedData, 0x00, 0x00, 0x02)       // lenght 3 bytes
	unencryptedData = append(unencryptedData, 0x00, 0x00)             // payload lenght 2 bytes

	con.transcript = append(con.transcript, unencryptedData...)

	unencryptedData = append(unencryptedData, 0x16) // denode end of encryptedData

	// 2. Pre-calculate the GCM Ciphertext Length (Plaintext + 16-byte GCM tag)
	ciphertextLen := len(unencryptedData) + 16

	aad := make([]byte, 5)
	aad[0] = ApplicationData // 0x17
	aad[1] = 0x03            // Legacy Version High
	aad[2] = 0x03            // Legacy Version Low
	binary.BigEndian.PutUint16(aad[3:5], uint16(ciphertextLen))

	encryptedData, err := EncryptRecord(unencryptedData, aad, con.serverHandshakeKey, con.serverHandshakeIV, con.handshakeSeq)
	if err != nil {
		return nil, err
	}

	handshakeHeaderLen := len(encryptedData)

	totalLength := recordHeaderLen + handshakeHeaderLen

	result := make([]byte, 0, totalLength)

	// record header
	result = append(result, ApplicationData, 0x03, 0x03) // type and version 3 bytes
	recordLenBytes := [2]byte{}
	binary.BigEndian.PutUint16(recordLenBytes[:], uint16(handshakeHeaderLen))
	result = append(result, recordLenBytes[:]...) // length 2 bytes

	con.handshakeSeq += 1

	result = append(result, encryptedData...) //

	return &result, nil
}

func createDynamicServerHello(con *SecureConn, message *TLSMessage, publicKey *[]byte) *[]byte {
	echoSessionID := message.HelloPayload.legacySessionID
	echoLength := byte(len(echoSessionID))
	random := make([]byte, 32)
	rand.Read(random)

	recordHeaderLen := 5    // 0x16, 0x03, 0x01 + 2 bytes length
	handshakeHeaderLen := 4 // TLSServerHello + 3 bytes length

	payloadLen := 2 + // version (0x03, 0x03)
		32 + // random
		1 + int(echoLength) + // session ID len + session ID
		2 + // cipher suite
		1 + // compression
		2 + // extension length
		6 + // supported versions extension
		40 // key share extension (8 bytes header + 32 bytes public key)

	totalLength := recordHeaderLen + handshakeHeaderLen + payloadLen

	buf := make([]byte, 2)
	// Cast int to uint16 and write to the 2-byte buffer
	binary.BigEndian.PutUint16(buf, uint16(totalLength))

	result := make([]byte, 0, totalLength)
	// record header
	result = append(result, Handshake, 0x03, 0x03) // type and version 3 bytes
	recordLenBytes := [2]byte{}
	binary.BigEndian.PutUint16(recordLenBytes[:], uint16(handshakeHeaderLen+payloadLen))
	result = append(result, recordLenBytes[:]...) // length 2 bytes

	// handshake header
	result = append(result, TLSServerHello) // 1 byte
	handshakeLenBytes := [4]byte{}
	binary.BigEndian.PutUint32(handshakeLenBytes[:], uint32(payloadLen))
	result = append(result, handshakeLenBytes[1:]...) // lenght 3 bytes

	// handshake payload
	result = append(result, 0x03, 0x03)       // version 2 bytes
	result = append(result, random...)        // 32 bytes
	result = append(result, echoLength)       // 1 byte
	result = append(result, echoSessionID...) // echoLength bytes
	result = append(result, 0x13, 0x01)       // cipher suite 2 bytes
	result = append(result, 0x00)             // compression 1 byte
	result = append(result, 0x00, 0x2E)       // extension length 2 byte
	// supported version
	result = append(result, 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04) // 6 bytes
	//key share 40 bytes
	result = append(result, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20) //  8 bytes
	result = append(result, *publicKey...)                                  // 32 bytes

	// save to the transcript
	con.transcript = append(con.transcript, result[5:]...)

	return &result
}

func readClientHello(con *SecureConn) (TLSMessage, error) {
	message := TLSMessage{}
	recordHeader := RecordHeader{}
	handshakeHeader := HandshakeHeader{}
	payload := HelloPayload{}
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	readBuffer := *bufPtr

	header, err := readNBytes(con.conn, &readBuffer, 5)
	if err != nil {
		return TLSMessage{}, fmt.Errorf("error while reading handshake buffer, err: %s", err)
	}
	recordType := byte(header[0])
	recordHeader.contentType = recordType
	recordHeader.legacyVersion = [2]byte(header[1:3])

	//turn into useable int
	recordLength := header[3:]
	var recordPad [4]byte
	copy(recordPad[2:], recordLength)
	recordLengthInt := int(binary.BigEndian.Uint32(recordPad[:]))
	recordHeader.length = recordLengthInt

	message.recordHeader = recordHeader

	handshake, err := readNBytes(con.conn, &readBuffer, recordLengthInt)
	if err != nil {
		return TLSMessage{}, fmt.Errorf("error while reading handshake buffer, err: %s", err)
	}
	// save to the transcript
	con.transcript = append(con.transcript, handshake...)

	handshakeType := byte(handshake[0])
	handshakeHeader.handshakeType = handshakeType

	// turn into usable int
	handshakeLength := handshake[1:4]
	var pad [4]byte
	copy(pad[1:], handshakeLength)
	payloadLength := int(binary.BigEndian.Uint32(pad[:]))
	handshakeHeader.length = payloadLength

	message.handshakeHeader = handshakeHeader

	if recordLengthInt < payloadLength {
		return TLSMessage{}, fmt.Errorf("the payload is bigger than record, means the message splits out to 2 or more record, which is not allowed here")
	}

	payload.legacyVersion = [2]byte(handshake[4:6])
	payload.random = [32]byte(handshake[6 : 6+32])

	cursor := 6 + 32
	IDLength := int(handshake[cursor])
	cursor += 1
	LegacyID := handshake[cursor : cursor+IDLength]
	cursor += IDLength
	payload.legacySessionID = LegacyID

	cipherLength := int(binary.BigEndian.Uint16(handshake[cursor : cursor+2]))
	cursor += 2

	payload.cipherSuites = handshake[cursor : cursor+cipherLength]
	cursor += cipherLength

	payload.legacyCompressionMethods = handshake[cursor : cursor+2]
	cursor += 2

	extensionLength := int(binary.BigEndian.Uint16(handshake[cursor : cursor+2]))
	cursor += 2

	extensions := handshake[cursor : cursor+extensionLength]
	payload.extensions = extensions

	// loop to find the ephemeral key
	i := 0
	for {
		exType := extensions[i : i+2]
		i += 2
		// key_share type
		// gemini helped
		if bytes.Equal(exType, []byte{0x00, 0x33}) {
			// Read total extension length
			// extLen := int(binary.BigEndian.Uint16(extensions[i : i+2]))
			i += 2

			// Read inner client shares list length
			listLen := int(binary.BigEndian.Uint16(extensions[i : i+2]))
			i += 2

			endOfList := i + listLen
			foundX25519 := false

			// Loop through all shares offered by the client
			for i < endOfList {
				group := binary.BigEndian.Uint16(extensions[i : i+2])
				i += 2

				keyLen := int(binary.BigEndian.Uint16(extensions[i : i+2]))
				i += 2

				if group == 0x001D { // X25519 Group ID
					pubKeyBytes := extensions[i : i+keyLen]
					pubKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
					if err != nil {
						return TLSMessage{}, fmt.Errorf("failed to parse public key: %v", err)
					}
					rawSecret, err := con.ServerPrivateKey.ECDH(pubKey)
					if err != nil {
						return TLSMessage{}, fmt.Errorf("ECDH failed: %v", err)
					}
					con.sharedSecretKey = rawSecret
					foundX25519 = true
					i += keyLen
					break
				} else {
					// Skip over this group's public key bytes to check the next one
					i += keyLen
				}
			}

			if !foundX25519 {
				return TLSMessage{}, fmt.Errorf("client did not offer a standard X25519 key share")
			}

			// Fast-forward cursor past the entire extension block
			i = endOfList
			break

		} else {
			skipLength := int(binary.BigEndian.Uint16(extensions[i : i+2]))
			i += 2          // skip the length
			i += skipLength //skip the data
		}
	}

	cursor += extensionLength
	if cursor != len(handshake) {
		return TLSMessage{}, fmt.Errorf("something went wrong, the number of byte parsed is incorrect")
	}

	message.HelloPayload = payload

	return message, nil
}

func readNBytes(con net.Conn, buffer *[]byte, n int) ([]byte, error) {
	// borrow the buffer but only use n amount of bytes
	readBuffer := (*buffer)[:n]
	bytes, err := io.ReadFull(con, readBuffer)
	if err != nil {
		return nil, err
	}
	result := readBuffer[:bytes]
	return result, nil
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

func handleClient(con *SecureConn) {
	defer con.conn.Close()

	contents, err := parseHTTPWithFSM(con)
	if err != nil {
		errorResponse := createServerErrorResponse(err)
		_, err = con.Write(errorResponse)
		if err != nil {
			_, _ = fmt.Printf("can't send response, err: %s", err)
			return
		}
		return
	}

	fmt.Printf("Request: %#v\n", contents)

	allowedMethod := []string{"GET", "POST", "QUERY"}
	method := contents.RequestLine.Method

	if !slices.Contains(allowedMethod, method) {
		_, _ = fmt.Printf("method [%s] not allowed\n", method)
		err = fmt.Errorf("method [%s] not allowed", method)
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

	fmt.Printf("finish send the response")
}

func handleUpgradeConnection(request *Request, con *SecureConn) error {
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

func writeWebsocketFrame(con *SecureConn, frame WebsocketFrame) error {
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

func handleWebsocketCon(request *Request, con *SecureConn) (int, error) {
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

func parseWebsocketFrame(con *SecureConn) (*WebsocketFrame, error) {
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

func parseHTTPWithFSM(con *SecureConn) (*Request, error) {
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
		fmt.Println(bytes)
		if bytes <= 0 {
			fmt.Println("error while reading bytes or finish reading")
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
