package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const (
	listenAddr    = "127.0.0.1:8080"
	upstreamProxy = "http://upstream.proxy.com:8080"
	username      = "yourUsername"
	password      = "yourPassword"
)

func main() {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		panic(fmt.Sprintf("Failed to start listener: %v", err))
	}
	fmt.Printf("Proxy listening on %s...\n", listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("Failed to accept connection: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	var err error

	clientReader := bufio.NewReader(clientConn)
	peek, err := clientReader.Peek(1)
	if err != nil {
		fmt.Printf("Failed to peek client connection: %v\n", err)
		return
	}

	// Route the connection based on protocol
	switch peek[0] {
	case 0x05: // SOCKS5
		err = handleSOCKS5(clientConn, clientReader)
	default: // HTTP/HTTPS
		var req *http.Request
		req, err = http.ReadRequest(clientReader)
		if err != nil {
			fmt.Printf("Failed to read request: %v\n", err)
			return
		}
		if req.Method == http.MethodConnect {
			err = handleHTTPSConnect(clientConn, req)
		} else {
			err = handleHTTPRequest(clientConn, req)
		}
	}

	if err != nil {
		fmt.Printf("Failed to handle connection: %v\n", err)
	}
}

func handleHTTPRequest(clientConn net.Conn, req *http.Request) error {
	upstreamConn, err := net.Dial("tcp", strings.TrimPrefix(upstreamProxy, "http://"))
	if err != nil {
		// fmt.Printf("Failed to connect to upstream proxy: %v\n", err)
		return err
	}
	defer upstreamConn.Close()

	// Add Proxy-Authorization header
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	req.Header.Set("Proxy-Authorization", "Basic "+auth)

	// Modify request for upstream proxy
	req.URL.Scheme = "http"
	req.URL.Host = req.Host
	req.RequestURI = "" // Clear RequestURI for client requests

	// Forward the request
	err = req.Write(upstreamConn)
	if err != nil {
		// fmt.Printf("Failed to forward request to upstream proxy: %v\n", err)
		return err
	}

	// Relay the response
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		// fmt.Printf("Failed to read response from upstream proxy: %v\n", err)
		return err
	}
	err = resp.Write(clientConn)
	return err
}

func handleHTTPSConnect(clientConn net.Conn, req *http.Request) error {
	upstreamConn, err := net.Dial("tcp", strings.TrimPrefix(upstreamProxy, "http://"))
	if err != nil {
		//fmt.Printf("Failed to connect to upstream proxy: %v\n", err)
		return err
	}
	defer upstreamConn.Close()

	// Send CONNECT request to the upstream proxy
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n", req.Host, auth)
	_, err = upstreamConn.Write([]byte(connectReq))
	if err != nil {
		//fmt.Printf("Failed to send CONNECT request: %v\n", err)
		return err
	}

	// Read response from the upstream proxy
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil || resp.StatusCode != http.StatusOK {
		//fmt.Printf("CONNECT failed: %v\n", err)
		return err
	}

	// Respond to the client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		//fmt.Printf("Failed to write CONNECT response to client: %v\n", err)
		return err
	}

	// Relay traffic between client and upstream proxy
	go io.Copy(upstreamConn, clientConn)
	_, err = io.Copy(clientConn, upstreamConn)

	return err
}

func handleSOCKS5(clientConn net.Conn, clientReader *bufio.Reader) error {
	// Step 1: SOCKS5 handshake
	buf := make([]byte, 2)
	_, err := io.ReadFull(clientReader, buf)
	if err != nil || buf[0] != 0x05 {
		fmt.Printf("Invalid SOCKS5 handshake: %v\n", err)
		return err
	}

	methodsLength := int(buf[1])
	methods := make([]byte, methodsLength)
	_, err = io.ReadFull(clientReader, methods)
	if err != nil {
		fmt.Printf("Failed to read SOCKS5 methods: %v\n", err)
		return err
	}

	// Respond: No authentication required
	_, err = clientConn.Write([]byte{0x05, 0x00})
	if err != nil {
		return err
	}

	// Step 2: Read connection request
	buf = make([]byte, 4)
	_, err = io.ReadFull(clientReader, buf)
	if err != nil || buf[0] != 0x05 {
		fmt.Printf("Invalid SOCKS5 connection request: %v\n", err)
		return err
	}

	if buf[1] != 0x01 { // Only TCP connections supported
		_, err := clientConn.Write([]byte{0x05, 0x07})
		return err
	}

	// Resolve target address
	var targetAddr string
	if buf[3] == 0x01 { // IPv4
		ip := make([]byte, 4)
		_, err := io.ReadFull(clientReader, ip)
		if err != nil {
			return err
		}
		port := make([]byte, 2)
		_, err = io.ReadFull(clientReader, port)
		if err != nil {
			return err
		}
		targetAddr = fmt.Sprintf("%s:%d", net.IP(ip), int(port[0])<<8|int(port[1]))
	} else if buf[3] == 0x03 { // Domain name
		length, _ := clientReader.ReadByte()
		domain := make([]byte, length)
		_, err := io.ReadFull(clientReader, domain)
		if err != nil {
			return err
		}
		port := make([]byte, 2)
		_, err = io.ReadFull(clientReader, port)
		if err != nil {
			return err
		}
		targetAddr = fmt.Sprintf("%s:%d", domain, int(port[0])<<8|int(port[1]))
	} else {
		_, err := clientConn.Write([]byte{0x05, 0x08})
		return err
	}

	// Step 3: Establish connection to upstream proxy
	upstreamConn, err := net.Dial("tcp", strings.TrimPrefix(upstreamProxy, "http://"))
	if err != nil {
		clientConn.Write([]byte{0x05, 0x01})
		// fmt.Printf("Failed to connect to upstream proxy: %v\n", err)
		return err
	}
	defer upstreamConn.Close()

	// Step 4: Send CONNECT request to upstream proxy
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n", targetAddr, auth)
	_, err = upstreamConn.Write([]byte(connectReq))
	if err != nil {
		clientConn.Write([]byte{0x05, 0x01})
		// fmt.Printf("Failed to send CONNECT request to upstream proxy: %v\n", err)
		return err
	}

	// Step 5: Read response from upstream proxy
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		clientConn.Write([]byte{0x05, 0x01})
		// fmt.Printf("CONNECT request to upstream proxy failed: %v\n", err)
		return err
	}

	// Step 6: Respond to the client
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Step 7: Relay traffic between the client and the upstream proxy
	go io.Copy(upstreamConn, clientConn)
	_, err = io.Copy(clientConn, upstreamConn)
	return err
}
