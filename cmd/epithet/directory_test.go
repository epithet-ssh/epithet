package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/epithet-ssh/epithet/pkg/broker"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/stretchr/testify/require"
)

func TestDirectoryUsersListOutput(t *testing.T) {
	page := &facts.SCIMPage{Resources: []json.RawMessage{
		json.RawMessage(`{"userName":"alice","id":"resource-id","externalId":"subject-id","active":true,"urn:example:extension":{"large":9007199254740993}}`),
		json.RawMessage(`{"userName":"disabled\nuser","id":"id\t2","active":false}`),
	}}
	var output bytes.Buffer
	require.NoError(t, writeDirectoryPage(&output, page, "Users", false))
	require.Equal(t, "alice\tresource-id\tsubject-id\ttrue\n\"disabled\\nuser\"\t\"id\\t2\"\t\tfalse\n", output.String())
	output.Reset()
	require.NoError(t, writeDirectoryPage(&output, page, "Users", true))
	decoder := json.NewDecoder(&output)
	for _, expected := range page.Resources {
		var actual json.RawMessage
		require.NoError(t, decoder.Decode(&actual))
		require.Equal(t, string(expected), string(actual))
	}
	output.Reset()
	require.NoError(t, writeDirectoryPage(&output, &facts.SCIMPage{}, "Users", true))
	require.Empty(t, output.String())
}

func TestDirectoryUsersCommand(t *testing.T) {
	var root struct {
		Directory DirectoryCLI `cmd:"directory"`
	}
	parser, err := kong.New(&root)
	require.NoError(t, err)
	_, err = parser.Parse([]string{"directory", "users", "list", "--json", "--agent-name", "work"})
	require.NoError(t, err)
	require.True(t, root.Directory.Users.List.JSON)
	require.Equal(t, "work", root.Directory.Name)
}

func TestDirectoryGroupsListOutput(t *testing.T) {
	page := &facts.SCIMPage{Resources: []json.RawMessage{
		json.RawMessage(`{"id":"group-ops","displayName":"ops","members":[{"value":"alice"}],"urn:example:extension":{"large":9007199254740993}}`),
		json.RawMessage(`{"id":"id\t2","displayName":"ops\nadmin"}`),
	}}
	var output bytes.Buffer
	require.NoError(t, writeDirectoryPage(&output, page, "Groups", false))
	require.Equal(t, "group-ops\tops\n\"id\\t2\"\t\"ops\\nadmin\"\n", output.String())
	output.Reset()
	require.NoError(t, writeDirectoryPage(&output, page, "Groups", true))
	decoder := json.NewDecoder(&output)
	for _, expected := range page.Resources {
		var actual json.RawMessage
		require.NoError(t, decoder.Decode(&actual))
		require.Equal(t, string(expected), string(actual))
	}
}

func TestDirectoryConsumesPagesBeforeFetchingNext(t *testing.T) {
	for _, resource := range []string{"Users", "Groups"} {
		t.Run(resource, func(t *testing.T) {
			for _, failSecond := range []bool{false, true} {
				t.Run(fmt.Sprint(failSecond), func(t *testing.T) {
					dir, err := os.MkdirTemp("/tmp", "epithet-scim-")
					require.NoError(t, err)
					t.Cleanup(func() { os.RemoveAll(dir) })
					socket := filepath.Join(dir, "b.sock")
					listener, err := net.Listen("unix", socket)
					require.NoError(t, err)
					t.Cleanup(func() { listener.Close() })
					var output directoryOutputBuffer
					var progress bytes.Buffer
					done := make(chan struct{})
					go func() {
						defer close(done)
						for _, start := range []int{1, 3} {
							conn, err := listener.Accept()
							if err != nil {
								return
							}
							var req broker.Request
							if json.NewDecoder(conn).Decode(&req) != nil {
								conn.Close()
								return
							}
							if req.DirectoryList == nil || req.DirectoryList.Resource != resource || req.DirectoryList.StartIndex != start {
								t.Error("unexpected page request")
								conn.Close()
								return
							}
							// Inspect output only after receiving the next request. The CLI must have
							// completed writing the previous page before it can issue that request.
							if start == 3 && !strings.Contains(output.String(), `"id":"two"`) {
								t.Error("first page was not emitted")
							}
							response := &broker.DirectoryListResponse{Page: &facts.SCIMPage{StartIndex: start, TotalResults: 3}}
							if start == 1 {
								response.Page.Resources = []json.RawMessage{json.RawMessage(`{"id":"one"}`), json.RawMessage(`{"id":"two"}`)}
							} else if failSecond {
								response = &broker.DirectoryListResponse{Error: "provider failed"}
							} else {
								response.Page.Resources = []json.RawMessage{json.RawMessage(`{"id":"three"}`)}
							}
							_ = json.NewEncoder(conn).Encode(broker.Event{DirectoryList: response})
							conn.Close()
						}
					}()
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					err = listDirectory(ctx, brokerClient{socket: socket}, resource, true, &output, &progress)
					if failSecond {
						require.ErrorContains(t, err, "provider failed")
					} else {
						require.NoError(t, err)
					}
					<-done
					expected := "{\"id\":\"one\"}\n{\"id\":\"two\"}\n"
					if !failSecond {
						expected += "{\"id\":\"three\"}\n"
					}
					require.Equal(t, expected, output.String())
				})
			}
		})
	}
}

// The fake broker observes output from its own goroutine between page requests.
type directoryOutputBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *directoryOutputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *directoryOutputBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
