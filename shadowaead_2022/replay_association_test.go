package shadowaead_2022

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	C "github.com/sagernet/sing-shadowsocks2/cipher"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type replayQueue struct {
	packets  [][]byte
	terminal error
	issued   []*buf.Buffer
}

func (q *replayQueue) next() ([]byte, error) {
	if len(q.packets) == 0 {
		if q.terminal != nil {
			return nil, q.terminal
		}
		return nil, io.EOF
	}
	packet := q.packets[0]
	q.packets = q.packets[1:]
	return packet, nil
}

func (q *replayQueue) Read(p []byte) (int, error) {
	packet, err := q.next()
	if err != nil {
		return 0, err
	}
	return copy(p, packet), nil
}

func (q *replayQueue) ReadBuffer(buffer *buf.Buffer) error {
	packet, err := q.next()
	if err != nil {
		return err
	}
	_, err = buffer.Write(packet)
	return err
}

func (q *replayQueue) InitializeReadWaiter(N.ReadWaitOptions) bool { return false }

func (q *replayQueue) WaitReadBuffer() (*buf.Buffer, error) {
	packet, err := q.next()
	if err != nil {
		return nil, err
	}
	buffer := buf.NewSize(len(packet))
	_, err = buffer.Write(packet)
	q.issued = append(q.issued, buffer)
	return buffer, err
}

func replayClient(t *testing.T, methodName string) *clientPacketConn {
	t.Helper()
	keyLength := 16
	if methodName != "2022-blake3-aes-128-gcm" {
		keyLength = 32
	}
	method, err := NewMethod(context.Background(), methodName, C.MethodOptions{KeyList: [][]byte{bytes.Repeat([]byte{7}, keyLength)}})
	if err != nil {
		t.Fatal(err)
	}
	clientMethod := method.(*Method)
	return &clientPacketConn{method: clientMethod, session: clientMethod.newUDPSession()}
}

func serverDatagram(t *testing.T, client *clientPacketConn, packetID uint64, payload string) []byte {
	t.Helper()
	serverSessionID := uint64(0x123456789abcdef0)
	header := make([]byte, 16)
	binary.BigEndian.PutUint64(header, serverSessionID)
	binary.BigEndian.PutUint64(header[8:], packetID)
	var body bytes.Buffer
	body.WriteByte(HeaderTypeServer)
	if err := binary.Write(&body, binary.BigEndian, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&body, binary.BigEndian, client.session.sessionId); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&body, binary.BigEndian, uint16(0)); err != nil {
		t.Fatal(err)
	}
	if err := M.SocksaddrSerializer.WriteAddrPort(&body, M.ParseSocksaddr("192.0.2.1:12345")); err != nil {
		t.Fatal(err)
	}
	body.WriteString(payload)
	if client.method.udpCipher != nil {
		nonce := bytes.Repeat([]byte{9}, PacketNonceSize)
		binary.BigEndian.PutUint64(nonce, packetID)
		plain := append(append([]byte{}, header...), body.Bytes()...)
		return client.method.udpCipher.Seal(nonce, nonce, plain, nil)
	}
	key := SessionKey(client.method.pskList[0], header[:8], client.method.keySaltLength)
	aead, err := client.method.constructor(key)
	if err != nil {
		t.Fatal(err)
	}
	packet := aead.Seal(append([]byte{}, header...), header[4:], body.Bytes(), nil)
	client.method.udpBlockEncryptCipher.Encrypt(packet[:16], packet[:16])
	return packet
}

func replayRead(t *testing.T, client *clientPacketConn, queue *replayQueue, api string) ([]byte, error) {
	t.Helper()
	switch api {
	case "ReadPacket":
		buffer := buf.NewSize(2048)
		defer buffer.Release()
		buffer.Resize(96, 0)
		buffer.Reserve(32)
		capacity := buffer.Cap()
		_, err := client.ReadPacket(buffer)
		if buffer.Cap() != capacity {
			t.Fatal("rear headroom changed")
		}
		if err == nil && buffer.Start() < 96 {
			t.Fatal("front headroom lost")
		}
		return append([]byte{}, buffer.Bytes()...), err
	case "ReadFrom":
		packet := make([]byte, 2048)
		n, _, err := client.ReadFrom(packet)
		return append([]byte{}, packet[:n]...), err
	case "WaitReadPacket":
		waiter := &clientPacketReadWaiter{clientPacketConn: client, readWaiter: queue}
		buffer, _, err := waiter.WaitReadPacket()
		if buffer != nil {
			defer buffer.Release()
			return append([]byte{}, buffer.Bytes()...), err
		}
		return nil, err
	}
	panic(api)
}

func TestReplayDoesNotCloseAssociation(t *testing.T) {
	for _, method := range MethodList {
		for _, api := range []string{"ReadPacket", "ReadFrom", "WaitReadPacket"} {
			t.Run(method+"/"+api, func(t *testing.T) {
				client := replayClient(t, method)
				first := serverDatagram(t, client, 9000, "first")
				duplicate := append([]byte{}, first...)
				queue := &replayQueue{packets: [][]byte{
					first,
					duplicate,
					serverDatagram(t, client, 0, "too-old"),
					serverDatagram(t, client, 9002, "new"),
					serverDatagram(t, client, 9001, "reordered"),
				}}
				client.reader = queue
				for _, want := range []string{"first", "new", "reordered"} {
					got, err := replayRead(t, client, queue, api)
					if err != nil || string(got) != want {
						t.Fatalf("got %q, %v; want %q", got, err, want)
					}
				}
				if len(queue.packets) != 0 {
					t.Fatal("unexpected unread packets")
				}
				if api == "WaitReadPacket" {
					for _, buffer := range queue.issued {
						if buffer.Cap() != 0 {
							t.Fatal("owned buffer not released")
						}
					}
				}
			})
		}
	}
}

func TestReplayPreservesReadErrors(t *testing.T) {
	for _, api := range []string{"ReadPacket", "ReadFrom", "WaitReadPacket"} {
		t.Run(api, func(t *testing.T) {
			client := replayClient(t, MethodList[0])
			first := serverDatagram(t, client, 1, "first")
			queue := &replayQueue{packets: [][]byte{first, append([]byte{}, first...)}, terminal: os.ErrDeadlineExceeded}
			client.reader = queue
			if _, err := replayRead(t, client, queue, api); err != nil {
				t.Fatal(err)
			}
			if _, err := replayRead(t, client, queue, api); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("lost timeout: %v", err)
			}
		})
	}
}

func TestReplayDoesNotHideAuthenticationError(t *testing.T) {
	for _, api := range []string{"ReadPacket", "ReadFrom", "WaitReadPacket"} {
		t.Run(api, func(t *testing.T) {
			client := replayClient(t, MethodList[0])
			bad := serverDatagram(t, client, 1, "bad")
			bad[len(bad)-1] ^= 1
			queue := &replayQueue{packets: [][]byte{bad, serverDatagram(t, client, 2, "next")}}
			client.reader = queue
			if _, err := replayRead(t, client, queue, api); err == nil || err == ErrPacketIdNotUnique {
				t.Fatalf("authentication failure hidden: %v", err)
			}
			if len(queue.packets) != 1 {
				t.Fatal("non-replay error consumed another datagram")
			}
		})
	}
}
