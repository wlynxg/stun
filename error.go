package stun

import "github.com/pkg/errors"

var (
	InvalidData     = errors.New("invalid data")
	InvalidProtocol = errors.New("invalid protocol")
	InvalidPort     = errors.New("invalid port")
	InvalidAddr     = errors.New("invalid addr")
	InvalidHeader   = errors.New("header can't be nil")
)
