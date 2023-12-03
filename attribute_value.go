package stun

import (
	"encoding/binary"
	"net"
	"net/netip"
)

type AttributeValue interface {
	// Marshal convert structure to []byte
	Marshal(*Header) ([]byte, error)

	// Unmarshal convert byte stream to structure value
	Unmarshal(*Header, []byte) error
}

type baseAddrAttribute struct {
	Family ProtocolFamily
	Port   uint16
	Addr   netip.Addr
}

func (m *baseAddrAttribute) Marshal(*Header) ([]byte, error) {
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

func (m *baseAddrAttribute) Unmarshal(header *Header, buff []byte) error {
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

// MappedAddress
// https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.1
// https://datatracker.ietf.org/doc/html/rfc5389#autoid-39
// https://datatracker.ietf.org/doc/html/rfc8489#section-14.1
type MappedAddress struct {
	*baseAddrAttribute
}

// ResponseAddress
// https://datatracker.ietf.org/doc/html/rfc8489#section-14.1
type ResponseAddress struct {
	*baseAddrAttribute
}

type XORMappedAddress struct {
	Family ProtocolFamily
	Port   uint16
	Addr   netip.Addr
}

func (m *XORMappedAddress) Marshal(header *Header) ([]byte, error) {
	if header == nil {
		return nil, InvalidHeader
	}

	addrLength := 0
	switch m.Family {
	case ProtocolFamilyIPv4:
		addrLength = net.IPv4len
	case ProtocolFamilyIPv6:
		addrLength = net.IPv6len
	default:
		return nil, InvalidProtocol
	}

	if m.Port == 0 {
		return nil, InvalidPort
	}

	if m.Addr.IsValid() {
		return nil, InvalidAddr
	}

	buff := make([]byte, 4+addrLength)
	// Reserved
	buff[0] = 0
	// Family
	buff[1] = byte(m.Family)
	// Port
	binary.BigEndian.PutUint16(buff[2:4], m.Port^uint16(MagicCookie>>16))

	xorBuff := make([]byte, addrLength)
	binary.BigEndian.PutUint32(xorBuff, MagicCookie)
	if m.Family == ProtocolFamilyIPv6 {
		copy(xorBuff[net.IPv4len:], header.TransactionID[:])
	}

	// Addr
	copy(buff[4:], XOR(xorBuff, m.Addr.AsSlice()))
	return buff, nil
}

func (m *XORMappedAddress) Unmarshal(header *Header, buff []byte) error {
	if len(buff) < 8 {
		return InvalidData
	}

	if header == nil {
		return InvalidHeader
	}

	f := ProtocolFamily(buff[1])
	addrLength := 0
	switch f {
	case ProtocolFamilyIPv4:
		addrLength = net.IPv4len
	case ProtocolFamilyIPv6:
		addrLength = net.IPv6len
	default:
		return InvalidProtocol
	}

	m.Family = f
	m.Port = binary.BigEndian.Uint16(buff[2:4]) ^ uint16(MagicCookie>>16)

	// Addr
	xorBuff := make([]byte, addrLength)
	binary.BigEndian.PutUint32(xorBuff, MagicCookie)
	if m.Family == ProtocolFamilyIPv6 {
		copy(xorBuff[net.IPv4len:], header.TransactionID[:])
	}

	addr, ok := netip.AddrFromSlice(XOR(buff[4:], xorBuff))
	if !ok {
		return InvalidData
	}
	m.Addr = addr

	return nil
}
