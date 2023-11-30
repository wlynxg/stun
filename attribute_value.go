package stun

import (
	"encoding/binary"
	"net/netip"
)

type AttributeValue interface {
	// Marshal convert structure to []byte
	Marshal() ([]byte, error)

	// Unmarshal convert byte stream to structure value
	Unmarshal([]byte) error
}

// MappedAddress https://datatracker.ietf.org/doc/html/rfc5389#section-15.1
type MappedAddress struct {
	Family ProtocolFamily
	Port   uint16
	Addr   netip.Addr
}

func (m *MappedAddress) Marshal() ([]byte, error) {
	var (
		buff []byte
	)

	switch m.Family {
	case ProtocolFamilyIPv4:
		buff = make([]byte, 8)
	case ProtocolFamilyIPv6:
		buff = make([]byte, 20)
	default:
		return nil, InvalidProtocol
	}

	if m.Port == 0 {
		return nil, InvalidPort
	}

	if m.Addr.IsValid() {
		return nil, InvalidAddr
	}

	// Reserved
	buff[0] = 0
	// Family
	buff[1] = byte(m.Family)
	// Port
	binary.BigEndian.PutUint16(buff[2:4], m.Port)
	// Addr
	copy(buff[4:], m.Addr.AsSlice())
	return buff, nil
}

func (m *MappedAddress) Unmarshal(buff []byte) error {
	if len(buff) < 8 {
		return InvalidData
	}

	f := ProtocolFamily(buff[1])
	switch f {
	case ProtocolFamilyIPv4:
	case ProtocolFamilyIPv6:
		if len(buff) < 20 {
			return InvalidData
		}
	default:
		return InvalidData
	}

	m.Family = f
	m.Port = binary.BigEndian.Uint16(buff[2:4])
	addr, ok := netip.AddrFromSlice(buff[4:])
	if !ok {
		return InvalidData
	}
	m.Addr = addr
	return nil
}
