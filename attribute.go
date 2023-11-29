package stun

type Attribute struct {
	Type   AttributeType
	Length uint16
	Value  AttributeValue
}
