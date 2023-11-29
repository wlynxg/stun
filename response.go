package stun

import (
	"encoding/binary"
	"net/netip"

	"github.com/pkg/errors"
)

type Response struct {
	MessageType   int
	MessageLength int
	MagicCookie   uint32
	TransactionID TxID
	Attributes    map[AttributeType]IAttribute
}

func NewResponse(txid TxID, addrPort netip.AddrPort) []byte {
	if !addrPort.Addr().Is4() {
		return nil
	}

	var (
		buff   = make([]byte, 512)
		offset = 0
	)

	binary.BigEndian.PutUint16(buff[:offset+2], BindingResponse)
	offset += 2

	binary.BigEndian.PutUint16(buff[offset:offset+2], 12)
	offset += 2

	binary.BigEndian.PutUint32(buff[offset:offset+4], MagicCookie)
	offset += 2

	copy(buff[offset:], txid)
	offset += 12

	binary.BigEndian.PutUint16(buff[offset:offset+2], uint16(AttrMappedAddress))
	offset += 2

	binary.BigEndian.PutUint16(buff[offset:offset+2], 8)
	offset += 2

	buff[offset] = 0
	offset++

	binary.BigEndian.PutUint16(buff[offset:offset+2], uint16(ProtocolFamilyIPv4))
	offset += 2

	binary.BigEndian.PutUint16(buff[offset:offset+2], addrPort.Port())
	offset += 2

	ip := addrPort.Addr().As4()
	copy(buff[offset:], ip[:])
	offset += 4

	return buff[:offset]
}

func UnmarshalResponse(buff []byte, resp *Response) (int, error) {
	if len(buff) < ResponseHeaderSize {
		return 0, errors.New("invalid stun response packet")
	}

	var offset = 0

	if resp.Attributes == nil {
		resp.Attributes = make(map[AttributeType]IAttribute)
	}

	// set the MessageType
	if binary.BigEndian.Uint16(buff[offset:offset+2]) == BindingResponse {
		resp.MessageType = BindingResponse
	}
	offset += 2

	// set the MessageLength
	resp.MessageLength = int(binary.BigEndian.Uint16(buff[offset : offset+2]))
	offset += 2

	// set the MagicCookie
	resp.MagicCookie = binary.BigEndian.Uint32(buff[offset : offset+4])
	offset += 4

	// set the TransactionID
	resp.TransactionID = make(TxID, 12)
	copy(resp.TransactionID, buff[offset:offset+12])
	offset += 12

	old := offset
	for offset-old < resp.MessageLength {
		attribute := IAttribute{}

		// set AttributeType
		attribute.Type = AttributeType(binary.BigEndian.Uint16(buff[offset : offset+2]))
		offset += 2

		// set AttributeLength
		attribute.Length = int(binary.BigEndian.Uint16(buff[offset : offset+2]))
		offset += 2

		// don't parse comprehension-option
		if attribute.Type.Optional() {
			offset += attribute.Length
			offset += attribute.Length % Padding
		}

		// set AttributeReserved
		attribute.Reserved = int(buff[offset])
		offset += 1

		// set ProtocolFamily
		attribute.ProtocolFamily = ProtocolFamily(buff[offset])
		offset += 1

		// set Port
		attribute.Port = int(binary.BigEndian.Uint16(buff[offset : offset+2]))
		offset += 2

		// set IP
		attribute.IP = netip.AddrFrom4([4]byte{buff[offset], buff[offset+1], buff[offset+2], buff[offset+3]})
		offset += 4

		resp.Attributes[attribute.Type] = attribute
	}

	return offset, nil
}
