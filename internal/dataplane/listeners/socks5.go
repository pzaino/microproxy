package listeners

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	socks5Version       = 0x05
	socks5AuthNone      = 0x00
	socks5AuthUserPass  = 0x02
	socks5AuthNoMethods = 0xFF

	socks5CmdConnect = 0x01

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	socks5ReplySucceeded          = 0x00
	socks5ReplyGeneralFailure     = 0x01
	socks5ReplyConnectionNotAllow = 0x02
	socks5ReplyHostUnreachable    = 0x04
	socks5ReplyCommandNotSupport  = 0x07
	socks5ReplyAddressNotSupport  = 0x08
)

// SOCKS5AuthConfig controls handshake authentication behavior.
type SOCKS5AuthConfig struct {
	Username string
	Password string
}

func (c SOCKS5AuthConfig) RequiresUserPass() bool {
	return c.Username != "" || c.Password != ""
}

// SOCKS5ConnectRequest is the parsed destination from a CONNECT request.
type SOCKS5ConnectRequest struct {
	ATYP   byte
	Host   string
	Port   int
	Target string
}

// PerformSOCKS5Handshake negotiates auth and parses a CONNECT request.
func PerformSOCKS5Handshake(conn net.Conn, auth SOCKS5AuthConfig) (SOCKS5ConnectRequest, error) {
	reader := bufio.NewReader(conn)

	method, err := negotiateSOCKS5Method(reader, conn, auth)
	if err != nil {
		return SOCKS5ConnectRequest{}, err
	}
	if method == socks5AuthUserPass {
		if err := authenticateSOCKS5UserPass(reader, conn, auth); err != nil {
			return SOCKS5ConnectRequest{}, err
		}
	}

	request, err := readSOCKS5ConnectRequest(reader)
	if err != nil {
		return SOCKS5ConnectRequest{}, err
	}
	return request, nil
}

// WriteSOCKS5ConnectReply writes a reply and bind address to the client.
func WriteSOCKS5ConnectReply(conn net.Conn, status byte, bindAddr net.Addr) error {
	atyp := byte(socks5AtypIPv4)
	addrBytes := []byte{0, 0, 0, 0}
	portBytes := []byte{0, 0}

	host, port, err := splitHostPort(bindAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				atyp = socks5AtypIPv4
				addrBytes = v4
			} else {
				atyp = socks5AtypIPv6
				addrBytes = ip.To16()
			}
		} else {
			atyp = socks5AtypDomain
			addrBytes = append([]byte{byte(len(host))}, []byte(host)...)
		}
		portBytes = []byte{byte(port >> 8), byte(port)}
	}

	reply := []byte{socks5Version, status, 0x00, atyp}
	reply = append(reply, addrBytes...)
	reply = append(reply, portBytes...)
	_, err = conn.Write(reply)
	return err
}

func negotiateSOCKS5Method(reader *bufio.Reader, conn net.Conn, auth SOCKS5AuthConfig) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, err
	}
	if header[0] != socks5Version {
		return 0, fmt.Errorf("unsupported socks version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return 0, err
	}

	wantMethod := byte(socks5AuthNone)
	if auth.RequiresUserPass() {
		wantMethod = socks5AuthUserPass
	}

	for _, method := range methods {
		if method == wantMethod {
			if _, err := conn.Write([]byte{socks5Version, wantMethod}); err != nil {
				return 0, err
			}
			return wantMethod, nil
		}
	}

	_, _ = conn.Write([]byte{socks5Version, socks5AuthNoMethods})
	return 0, errors.New("no compatible socks5 auth method")
}

func authenticateSOCKS5UserPass(reader *bufio.Reader, conn net.Conn, auth SOCKS5AuthConfig) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("unsupported auth version %d", header[0])
	}

	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(reader, plen); err != nil {
		return err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(reader, pass); err != nil {
		return err
	}

	if string(user) != auth.Username || string(pass) != auth.Password {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("invalid socks5 username/password")
	}

	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func readSOCKS5ConnectRequest(reader *bufio.Reader) (SOCKS5ConnectRequest, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(reader, head); err != nil {
		return SOCKS5ConnectRequest{}, err
	}
	if head[0] != socks5Version {
		return SOCKS5ConnectRequest{}, fmt.Errorf("unsupported request version %d", head[0])
	}
	if head[1] != socks5CmdConnect {
		return SOCKS5ConnectRequest{}, fmt.Errorf("unsupported socks5 command %d", head[1])
	}

	host, err := readSOCKS5Address(reader, head[3])
	if err != nil {
		return SOCKS5ConnectRequest{}, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return SOCKS5ConnectRequest{}, err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	return SOCKS5ConnectRequest{
		ATYP:   head[3],
		Host:   host,
		Port:   port,
		Target: net.JoinHostPort(host, strconv.Itoa(port)),
	}, nil
}

func readSOCKS5Address(reader *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case socks5AtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socks5AtypDomain:
		size := make([]byte, 1)
		if _, err := io.ReadFull(reader, size); err != nil {
			return "", err
		}
		buf := make([]byte, int(size[0]))
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case socks5AtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", fmt.Errorf("unsupported socks5 atyp %d", atyp)
	}
}

func splitHostPort(addr net.Addr) (string, int, error) {
	if addr == nil {
		return "", 0, errors.New("nil addr")
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
