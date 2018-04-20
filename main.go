package main

import (
"fmt"
"os"
	"net"
	"os/user"
	"strings"
	"os/signal"

	"golang.org/x/crypto/ssh"
)

func fail(code int, format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(code)
}

func main() {
	privateKeyPath := "~/.ssh/id_rsa"
	if strings.HasPrefix(privateKeyPath, "~/") {
		user, err := user.Current()
		if err == nil {
			privateKeyPath = strings.Replace(privateKeyPath, "~", user.HomeDir, 1)
		}
	}

	privateKey, err := ReadPrivateKey(privateKeyPath)
	if err != nil {
		fail(2, "Couldn't read private key: %v\n", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		fail(3, "Failed to parse key: %v\n", err)
	}

	auth := NewAuth()
	config := MakeAuth(auth)
	config.AddHostKey(signer)

	s, err := ListenSSH(":1221", config)
	if err != nil {
		fail(4, "Failed to listen on socket: %v\n", err)
	}
	defer s.Close()

	host := NewHost(s, auth)

	go host.Serve()

	// Construct interrupt handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	<-sig // Wait for ^C signal
	fmt.Fprintln(os.Stderr, "Interrupt signal detected, shutting down.")
	os.Exit(0)
}

// Container for the connection and ssh-related configuration
type SSHListener struct {
	net.Listener
	config *ssh.ServerConfig
	HandlerFunc func(*ssh.ServerConn, ssh.NewChannel)
}

// Make an SSH listener socket
func ListenSSH(laddr string, config *ssh.ServerConfig) (*SSHListener, error) {
	socket, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	l := SSHListener{Listener: socket, config: config}
	return &l, nil
}

func GetSession(conn *ssh.ServerConn, channels <-chan ssh.NewChannel) ssh.NewChannel {
	for ch := range channels {
		if t := ch.ChannelType(); t != "session" {
			fmt.Fprintf(os.Stderr, "[%s] Ignored channel type: %s\n", conn.RemoteAddr(), t)
			ch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}

		return ch
	}
	return nil
    }


// Accept incoming connections as terminal requests and yield them
func (l *SSHListener) Serve() {
	defer l.Close()
	for {
		conn, err := l.Accept()

		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to accept connection: %s\n", err)
			break
		}

		// Goroutineify to resume accepting sockets early
		go func() {
			sconn, chans, err := l.handleConn(conn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Failed to handshake: %s", conn.RemoteAddr(), err)
				return
			}
			l.HandlerFunc(sconn, GetSession(sconn, chans))
		}()
	}
}

func (l *SSHListener) handleConn(conn net.Conn) (*ssh.ServerConn, <-chan ssh.NewChannel, error) {
	// Upgrade TCP connection to SSH connection
	sshConn, channels, requests, err := ssh.NewServerConn(conn, l.config)
	if err != nil {
		return nil, nil, err
	}

	// FIXME: Disconnect if too many faulty requests? (Avoid DoS.)
	go ssh.DiscardRequests(requests)
	return sshConn, channels, nil
}
