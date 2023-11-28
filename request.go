package stun

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

type Request struct {
	MessageType   uint16
	MessageLength uint16
	MagicCookie   uint32
	TransactionID [12]byte
	Attribute     *ActionAttribute
}

func MarshalRequest(req *Request) []byte {
	if req == nil {
		return nil
	}

	var (
		buff   = make([]byte, 512)
		offset = 0
	)

	binary.BigEndian.PutUint16(buff[offset:offset+2], req.MessageType)
	offset += 2
	binary.BigEndian.PutUint16(buff[offset:offset+2], req.MessageLength)
	offset += 2
	binary.BigEndian.PutUint32(buff[offset:offset+4], req.MagicCookie)
	offset += 4
	copy(buff[offset:offset+12], req.TransactionID[:])
	offset += 12
	if req.Attribute != nil {
		binary.BigEndian.PutUint16(buff[offset:offset+2], uint16(req.Attribute.Type))
		offset += 2
		binary.BigEndian.PutUint16(buff[offset:offset+2], req.Attribute.Length)
		offset += 2
		binary.BigEndian.PutUint32(buff[offset:offset+4], uint32(req.Attribute.Action))
		offset += 4
	}

	return buff[:offset]
}

func UnmarshalRequest(buff []byte) (*Request, error) {
	if len(buff) < ResponseHeaderSize {
		return nil, errors.New("invalid stun response packet")
	}

	var (
		req    = &Request{}
		offset = 0
	)

	req.MessageType = binary.BigEndian.Uint16(buff[:2])
	offset += 2

	req.MessageLength = binary.BigEndian.Uint16(buff[offset : offset+2])
	offset += 2

	req.MagicCookie = binary.BigEndian.Uint32(buff[offset : offset+4])
	offset += 4

	txid := TxID{}
	copy(txid, buff[offset:offset+12])
	req.TransactionID = [12]byte(txid)

	return req, nil
}

func NewRequest(action ChangeRequestAction) *Request {
	var (
		req = &Request{}
	)

	// set the message type
	req.MessageType = BindingRequest

	// set the message length
	if action != NoAction {
		req.MessageLength = 8
	} else {
		req.MessageLength = 0
	}

	// set a magic cookie to be compatible with RFC3489
	req.MagicCookie = MagicCookie

	// set the TransactionID
	copy(req.TransactionID[:], NewTxID())

	switch action {
	case ChangePort:
		req.Attribute = &ActionAttribute{
			Type:   ChangeRequest,
			Length: 4,
			Action: ChangePort,
		}
	case ChangeIPAndPort:
		req.Attribute = &ActionAttribute{
			Type:   ChangeRequest,
			Length: 4,
			Action: ChangeIPAndPort,
		}
	}
	return req
}

func NewTxID() TxID {
	id := make(TxID, 12)
	io.ReadFull(rand.Reader, id)
	return id
}
