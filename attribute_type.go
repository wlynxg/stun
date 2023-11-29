package stun

// AttributeType is attribute type.
type AttributeType uint16

const (
	// AttrMappedAddress to AttrXORMappedAddress is from comprehension-required range (0x0000-0x7FFF)
	AttrMappedAddress     AttributeType = 0x0001 // MAPPED-ADDRESS
	AttrUsername          AttributeType = 0x0006 // USERNAME
	AttrMessageIntegrity  AttributeType = 0x0008 // MESSAGE-INTEGRITY
	AttrErrorCode         AttributeType = 0x0009 // ERROR-CODE
	AttrUnknownAttributes AttributeType = 0x000A // UNKNOWN-ATTRIBUTES
	AttrRealm             AttributeType = 0x0014 // REALM
	AttrNonce             AttributeType = 0x0015 // NONCE
	AttrXORMappedAddress  AttributeType = 0x0020 // XOR-MAPPED-ADDRESS

	// AttrSoftware to AttrFingerprint is from comprehension-optional range (0x8000-0xFFFF).
	AttrSoftware        AttributeType = 0x8022 // SOFTWARE
	AttrAlternateServer AttributeType = 0x8023 // ALTERNATE-SERVER
	AttrFingerprint     AttributeType = 0x8028 // FINGERPRINT

	// AttrPriority to AttrICEControlling is from RFC 5245 ICE.
	AttrPriority       AttributeType = 0x0024 // PRIORITY
	AttrUseCandidate   AttributeType = 0x0025 // USE-CANDIDATE
	AttrICEControlled  AttributeType = 0x8029 // ICE-CONTROLLED
	AttrICEControlling AttributeType = 0x802A // ICE-CONTROLLING

	// AttrChannelNumber to AttrReservationToken is from RFC 5766 TURN.
	AttrChannelNumber      AttributeType = 0x000C // CHANNEL-NUMBER
	AttrLifetime           AttributeType = 0x000D // LIFETIME
	AttrXORPeerAddress     AttributeType = 0x0012 // XOR-PEER-ADDRESS
	AttrData               AttributeType = 0x0013 // DATA
	AttrXORRelayedAddress  AttributeType = 0x0016 // XOR-RELAYED-ADDRESS
	AttrEvenPort           AttributeType = 0x0018 // EVEN-PORT
	AttrRequestedTransport AttributeType = 0x0019 // REQUESTED-TRANSPORT
	AttrDontFragment       AttributeType = 0x001A // DONT-FRAGMENT
	AttrReservationToken   AttributeType = 0x0022 // RESERVATION-TOKEN

	// AttrChangeRequest to AttrOtherAddress is from RFC 5780 NAT Behavior Discovery
	AttrChangeRequest  AttributeType = 0x0003 // CHANGE-REQUEST
	AttrPadding        AttributeType = 0x0026 // PADDING
	AttrResponsePort   AttributeType = 0x0027 // RESPONSE-PORT
	AttrCacheTimeout   AttributeType = 0x8027 // CACHE-TIMEOUT
	AttrResponseOrigin AttributeType = 0x802b // RESPONSE-ORIGIN
	AttrOtherAddress   AttributeType = 0x802C // OTHER-ADDRESS

	// AttrSourceAddress and AttrChangedAddress from RFC 3489, removed by RFC 5389,
	// but still used by RFC5389-implementing software like Vovida.org, reTURNServer, etc.
	AttrSourceAddress  AttributeType = 0x0004 // SOURCE-ADDRESS
	AttrChangedAddress AttributeType = 0x0005 // CHANGED-ADDRESS

	// AttrConnectionID from RFC 6062 TURN Extensions for TCP Allocations.
	AttrConnectionID AttributeType = 0x002a // CONNECTION-ID

	// AttrRequestedAddressFamily from RFC 6156 TURN IPv6.
	AttrRequestedAddressFamily AttributeType = 0x0017 // REQUESTED-ADDRESS-FAMILY

	// AttrOrigin from An Origin Attribute for the STUN Protocol.
	AttrOrigin AttributeType = 0x802F

	// AttrMessageIntegritySHA256 to AttrAlternateDomain is from RFC 8489 STUN.
	AttrMessageIntegritySHA256 AttributeType = 0x001C // MESSAGE-INTEGRITY-SHA256
	AttrPasswordAlgorithm      AttributeType = 0x001D // PASSWORD-ALGORITHM
	AttrUserhash               AttributeType = 0x001E // USERHASH
	AttrPasswordAlgorithms     AttributeType = 0x8002 // PASSWORD-ALGORITHMS
	AttrAlternateDomain        AttributeType = 0x8003 // ALTERNATE-DOMAIN
)

// Required returns true if type is from comprehension-required range (0x0000-0x7FFF).
func (t AttributeType) Required() bool {
	return t <= 0x7FFF
}

// Optional returns true if type is from comprehension-optional range (0x8000-0xFFFF).
func (t AttributeType) Optional() bool {
	return t >= 0x8000
}

// String returns AttributeType's name.
func (t AttributeType) String() string {
	attrNameMap := map[AttributeType]string{
		AttrMappedAddress:          "MAPPED-ADDRESS",
		AttrUsername:               "USERNAME",
		AttrErrorCode:              "ERROR-CODE",
		AttrMessageIntegrity:       "MESSAGE-INTEGRITY",
		AttrUnknownAttributes:      "UNKNOWN-ATTRIBUTES",
		AttrRealm:                  "REALM",
		AttrNonce:                  "NONCE",
		AttrXORMappedAddress:       "XOR-MAPPED-ADDRESS",
		AttrSoftware:               "SOFTWARE",
		AttrAlternateServer:        "ALTERNATE-SERVER",
		AttrFingerprint:            "FINGERPRINT",
		AttrPriority:               "PRIORITY",
		AttrUseCandidate:           "USE-CANDIDATE",
		AttrICEControlled:          "ICE-CONTROLLED",
		AttrICEControlling:         "ICE-CONTROLLING",
		AttrChannelNumber:          "CHANNEL-NUMBER",
		AttrLifetime:               "LIFETIME",
		AttrXORPeerAddress:         "XOR-PEER-ADDRESS",
		AttrData:                   "DATA",
		AttrXORRelayedAddress:      "XOR-RELAYED-ADDRESS",
		AttrEvenPort:               "EVEN-PORT",
		AttrRequestedTransport:     "REQUESTED-TRANSPORT",
		AttrDontFragment:           "DONT-FRAGMENT",
		AttrReservationToken:       "RESERVATION-TOKEN",
		AttrConnectionID:           "CONNECTION-ID",
		AttrRequestedAddressFamily: "REQUESTED-ADDRESS-FAMILY",
		AttrMessageIntegritySHA256: "MESSAGE-INTEGRITY-SHA256",
		AttrPasswordAlgorithm:      "PASSWORD-ALGORITHM",
		AttrUserhash:               "USERHASH",
		AttrPasswordAlgorithms:     "PASSWORD-ALGORITHMS",
		AttrAlternateDomain:        "ALTERNATE-DOMAIN",
	}

	if name, ok := attrNameMap[t]; ok {
		return name
	}
	return ""
}
