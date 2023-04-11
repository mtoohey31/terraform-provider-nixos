package sshtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Response contains information about how an ssh "exec" request should be
// responded to.
type Response struct {
	// Stdout is the standard output that should be reported.
	Stdout []byte
	// Status is the "exit-status" that should be reported.
	Status uint32
}

// Server is an ssh test server.
type Server struct {
	// Addr is the address at which the server can be accessed.
	Addr net.Addr
	// PublicKey is the public key of the test server.
	PublicKey ssh.PublicKey
	// ClientPrivateKey is the only private key that can be used to
	// authenticate with the server.
	ClientPrivateKey ed25519.PrivateKey

	// execDataMu protects execReqeusts and execResponses.
	execDataMu sync.Mutex
	// execRequests are the "exec" requests that have been made since the last
	// call to Reset.
	execRequests []string
	// execResponses defines how "exec" requests should be responded to.
	// Elements are popped from the slice each time a request is made.
	execResponses map[string][]Response
}

// PublicKeyString returns the marshalled form of s.PublicKey in
// authorized_keys format.
func (s *Server) PublicKeyString() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey)))
}

// Requests returns the requests that have been made since the last call to
// Reset (or since the server was constructed).
func (s *Server) Requests() []string {
	s.execDataMu.Lock()
	defer s.execDataMu.Unlock()
	return s.execRequests
}

// Reset clears the recorded exec requests and sets the updated responses.
func (s *Server) Reset(execResponses map[string][]Response) {
	s.execDataMu.Lock()
	defer s.execDataMu.Unlock()
	s.execRequests = []string{}
	s.execResponses = execResponses
}

// NewKeyAuthServer creates and starts a new Server. It will be automatically
// closed when the test ends.
func NewKeyAuthServer(t *testing.T) *Server {
	s := &Server{}

	// Key generation and conversion

	hostPubEd, hostPrivEd, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var clientPubEd ed25519.PublicKey
	clientPubEd, s.ClientPrivateKey, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	s.PublicKey, err = ssh.NewPublicKey(hostPubEd)
	require.NoError(t, err)
	clientPub, err := ssh.NewPublicKey(clientPubEd)
	require.NoError(t, err)

	hostPriv, err := ssh.NewSignerFromKey(hostPrivEd)
	require.NoError(t, err)

	// Server setup and conversion

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(clientPub.Marshal(), key.Marshal()) {
				return nil, fmt.Errorf("public key mismatch")
			}

			return &ssh.Permissions{}, nil
		},
	}
	serverConfig.AddHostKey(hostPriv)

	listener, err := net.Listen("tcp", "127.0.0.1:")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	s.Addr = listener.Addr()

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					fmt.Fprintln(os.Stderr, err)
				}
				return
			}
			defer nConn.Close()

			go func() {
				conn, channelCh, reqCh, err := ssh.NewServerConn(nConn, serverConfig)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to create server conn: %s\n", err)
					return
				}
				defer conn.Close()

				go ssh.DiscardRequests(reqCh)

				for channel := range channelCh {
					if channel.ChannelType() != "session" {
						fmt.Fprintf(os.Stderr, "non-session channel of type %s opened\n", channel.ChannelType())
						return
					}

					channel, reqCh, err := channel.Accept()
					if err != nil {
						if !errors.Is(err, net.ErrClosed) {
							fmt.Fprintf(os.Stderr, "accept failed: %s\n", err)
						}
						return
					}

					go func() {
						for req := range reqCh {
							if req.Type != "exec" {
								fmt.Fprintf(os.Stderr, "non-exec request of type %s made\n", req.Type)
								conn.Close()
								return
							}

							if err := req.Reply(true, nil); err != nil {
								fmt.Fprintf(os.Stderr, "reply failed: %s\n", err)
								conn.Close()
								return
							}

							var payload struct{ Value string }
							if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
								fmt.Fprintf(os.Stderr, "unmarshal failed: %s\n", err)
								conn.Close()
								return
							}

							if s.execResponses == nil {
								fmt.Fprintf(os.Stderr, "unexpected exec request payload: %s\n", payload.Value)
								conn.Close()
								return
							}

							s.execDataMu.Lock()
							s.execRequests = append(s.execRequests, payload.Value)
							responses, ok := s.execResponses[payload.Value]
							if !ok {
								fmt.Fprintf(os.Stderr, "unexpected exec request payload: %s\n", payload.Value)
								conn.Close()
								return
							}
							if len(responses) == 0 {
								s.execDataMu.Unlock()
								fmt.Fprintf(os.Stderr, "unexpected exec request payload: %s\n", payload.Value)
								conn.Close()
								return
							}
							response := responses[0]
							s.execResponses[payload.Value] = responses[1:]
							s.execDataMu.Unlock()

							if _, err := channel.Write(response.Stdout); err != nil {
								fmt.Fprintf(os.Stderr, "failed to write response: %s\n", err)
								conn.Close()
								return
							}

							exitStatusPayload := ssh.Marshal(struct{ Status uint32 }{response.Status})
							reply, err := channel.SendRequest("exit-status", false, exitStatusPayload)
							if err != nil {
								fmt.Fprintf(os.Stderr, "failed to send exit-status request: %s\n", err)
								conn.Close()
								return
							}
							if reply {
								fmt.Fprintln(os.Stderr, "exit-status request unexpectedly required reply")
								conn.Close()
								return
							}
						}
					}()

					go func() {
						if _, err := io.Copy(io.Discard, channel); err != nil {
							fmt.Fprintf(os.Stderr, "copying stdin failed: %s\n", err)
							conn.Close()
						}
						channel.Close()
					}()
				}
			}()
		}
	}()

	return s
}
