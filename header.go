package stun

type Header struct {
	MessageType   uint16
	MessageLength uint16
	MagicCookie   uint32
	TransactionID [12]byte
}
