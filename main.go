package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	listenAddr  string
	backendAddr string
	logger      *logrus.Logger
)

func init() {
	logger = logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	flag.StringVar(&listenAddr, "listen", "0.0.0.0:445", "Address to listen on")
	flag.StringVar(&backendAddr, "backend", "192.168.4.101:445", "Address of the backend SMB server")
}

func main() {
	flag.Parse()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	logger.Infof("SMB Proxy listening on %s, backend: %s", listenAddr, backendAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			logger.Errorf("Failed to accept connection: %v", err)
			continue
		}

		logger.Infof("New connection from %s", clientConn.RemoteAddr())
		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	logger.Infof("Handling connection from %s", clientConn.RemoteAddr())

	backendConn, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		logger.Errorf("Failed to connect to backend server %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	logger.Infof("Connected to backend server %s", backendAddr)

	errChan := make(chan error, 2)
	go proxyTraffic(clientConn, backendConn, "Client -> Backend", errChan)
	go proxyTraffic(backendConn, clientConn, "Backend -> Client", errChan)

	// Wait for EOF or error
	for i := 0; i < 2; i++ {
		err := <-errChan
		if err == io.EOF {
			logger.Infof("Connection closed normally")
		} else if err != nil {
			logger.Errorf("Proxy error: %v", err)
		}
	}

	logger.Infof("Closing connection from %s", clientConn.RemoteAddr())
}

func proxyTraffic(src, dst net.Conn, direction string, errChan chan<- error) {
	buffer := make([]byte, 4096)
	for {
		n, err := src.Read(buffer)
		if err != nil {
			errChan <- err
			return
		}

		data := buffer[:n]
		logger.Debugf("%s: %d bytes", direction, n)
		logger.Debugf("Raw data:\n%s", hex.Dump(data))

		parseSMBPacket(data)

		_, err = dst.Write(data)
		if err != nil {
			errChan <- fmt.Errorf("%s write error: %v", direction, err)
			return
		}
	}
}

func parseSMBPacket(data []byte) {
	if len(data) < 8 {
		logger.Warn("Packet too short to be NetBIOS + SMB")
		return
	}

	// Parse NetBIOS Session Service header
	length := binary.BigEndian.Uint32(data[0:4])
	logger.Infof("NetBIOS Length: %d", length)

	// Check for SMB2/3 magic number
	if string(data[4:8]) != "\xFESMB" {
		logger.Warn("Not an SMB2/3 packet")
		return
	}

	logger.Info("Detected SMB2/3 packet")

	// SMB2/3 structure starts at offset 4
	smbData := data[4:]

	// Parse SMB2/3 header
	if len(smbData) < 64 {
		logger.Warn("SMB2/3 packet too short")
		return
	}

	// Extract fields from SMB2/3 header
	structureSize := binary.LittleEndian.Uint16(smbData[0:2])
	creditCharge := binary.LittleEndian.Uint16(smbData[2:4])
	status := binary.LittleEndian.Uint32(smbData[8:12])
	command := binary.LittleEndian.Uint16(smbData[12:14])
	creditRequestResponse := binary.LittleEndian.Uint16(smbData[14:16])
	flags := binary.LittleEndian.Uint32(smbData[16:20])
	nextCommand := binary.LittleEndian.Uint32(smbData[20:24])
	messageId := binary.LittleEndian.Uint64(smbData[24:32])

	logger.Infof("Structure Size: %d", structureSize)
	logger.Infof("Credit Charge: %d", creditCharge)
	logger.Infof("Status: 0x%08X", status)
	logger.Infof("Command: 0x%04X", command)
	logger.Infof("Credit Request/Response: %d", creditRequestResponse)
	logger.Infof("Flags: 0x%08X", flags)
	logger.Infof("Next Command: 0x%08X", nextCommand)
	logger.Infof("Message ID: %d", messageId)

	if negotiatedDialect >= 0x0300 {
		parseSMB3Packet(smbData)
	} else {
		parseSMB2Packet(smbData)
	}
}

func parseSMB2Packet(data []byte) {
	if len(data) < 64 {
		logger.Warn("SMB2 packet too short")
		return
	}

	command := binary.LittleEndian.Uint16(data[12:14])
	logger.Infof("SMB2 Command: 0x%04X", command)

	switch command {
	case 0x0000:
		logger.Info("SMB2 NEGOTIATE")
		parseNegotiate(data)
	case 0x0001:
		logger.Info("SMB2 SESSION_SETUP")
		parseSessionSetup(data)
	default:
		logger.Infof("Unhandled SMB2 command: 0x%04X", command)
	}
}

func parseSMB3Packet(data []byte) {
	if len(data) < 64 {
		logger.Warn("SMB3 packet too short")
		return
	}

	command := binary.LittleEndian.Uint16(data[12:14])
	logger.Infof("SMB3 Command: 0x%04X", command)

	switch command {
	case 0x0000:
		logger.Info("SMB3 NEGOTIATE")
		parseNegotiate(data)
	case 0x0001:
		logger.Info("SMB3 SESSION_SETUP")
		parseSessionSetup(data)
	default:
		logger.Infof("Unhandled SMB3 command: 0x%04X", command)
	}

	// Add SMB3-specific parsing here if needed
}

var negotiatedDialect uint16

func parseNegotiate(data []byte) {
	if len(data) < 36 {
		logger.Warn("NEGOTIATE packet too short")
		return
	}

	dialectCount := binary.LittleEndian.Uint16(data[22:24])
	logger.Infof("Dialect Count: %d", dialectCount)

	for i := 0; i < int(dialectCount); i++ {
		offset := 36 + i*2
		if offset+2 > len(data) {
			logger.Warn("NEGOTIATE packet too short for all dialects")
			return
		}
		dialect := binary.LittleEndian.Uint16(data[offset : offset+2])
		logger.Infof("Dialect: 0x%04X", dialect)

		// Store the highest dialect as the negotiated dialect
		if dialect > negotiatedDialect {
			negotiatedDialect = dialect
		}
	}

	logger.Infof("Negotiated Dialect: 0x%04X", negotiatedDialect)
}

func parseSessionSetup(data []byte) {
	if len(data) < 72 {
		logger.Warn("SESSION_SETUP packet too short")
		return
	}

	securityBufferOffset := binary.LittleEndian.Uint16(data[16:18])
	securityBufferLength := binary.LittleEndian.Uint16(data[18:20])

	if int(securityBufferOffset+securityBufferLength) > len(data) {
		logger.Warn("SESSION_SETUP packet too short for security buffer")
		return
	}

	securityBuffer := data[securityBufferOffset : securityBufferOffset+securityBufferLength]
	logger.Infof("Security Buffer Length: %d", securityBufferLength)
	logger.Debugf("Security Buffer:\n%s", hex.Dump(securityBuffer))

	if len(securityBuffer) > 4 {
		logger.Infof("SPNEGO Token Type: 0x%02X", securityBuffer[0])
	}
}
