package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	typeMask = 0b111_00000
	argsMask = 0b000_11111
)

const (
	typeUInt   uint8 = iota << 5
	typeNegInt uint8 = iota << 5
	typeBytes  uint8 = iota << 5
	typeText   uint8 = iota << 5
	typeArray  uint8 = iota << 5
	typeMap    uint8 = iota << 5
)

func decodeCBOR(b []byte) (interface{}, []byte, error) {
	switch b[0] & typeMask {
	case typeUInt:
		return parseUint(b)
	case typeNegInt:
		return parseNegInt(b)
	case typeText:
		return parseText(b)
	case typeArray:
		return parseArray(b)
	case typeBytes:
		return parseBytes(b)
	case typeMap:
		return parseMap(b)
	default:
		return nil, nil, fmt.Errorf("Unable to parse %b", b[0])
	}
}

func parseUint(b []byte) (uint64, []byte, error) {
	t := b[0] & typeMask
	if t != typeUInt {
		return 0, nil, fmt.Errorf("Uint type was not passed in, got %b.", b[0])
	}
	return uint64(b[0] & argsMask), b[1:], nil
}

func parseNegInt(b []byte) (int, []byte, error) {
	t := b[0] & typeMask
	if t != typeNegInt {
		return 0, nil, fmt.Errorf("NegInt type was not passed in, got %b.", b[0])
	}
	return -1 - int(b[0]&argsMask), b[1:], nil
}

func parseBytes(b []byte) ([]byte, []byte, error) {
	t := b[0] & typeMask
	if t != typeBytes {
		return nil, nil, fmt.Errorf("Bytes type was not passed in, got %b.", b[0])
	}

	length := 0
	arg := b[0] & argsMask
	if arg < 24 {
		length = int(arg)
		// b[0] is the type AND length
		return b[1 : 1+length], b[1+length:], nil
	}
	if arg == 24 {
		length = int(b[1])
		// b[0] is the type, b[1] is the # of bytes
		return b[2 : 2+length], b[2+length:], nil
	}
	if arg == 25 {
		length = int(binary.BigEndian.Uint16(b[1:3]))
		// b[0] is the type, b[1], b[2] are the # of bytes.
		return b[3 : 3+length], b[3+length:], nil
	}
	if arg == 26 {
		length = int(binary.BigEndian.Uint32(b[1:5]))
		// b[0] is the type, b[1], b[2], b[3], b[4] are the # of bytes.
		return b[5 : 5+length], b[5+length:], nil
	}
	if arg == 27 {
		length = int(binary.BigEndian.Uint64(b[1:9]))
		// b[0] is the type, b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8] are the # of bytes.
		return b[9 : 9+length], b[9+length:], nil
	}
	// arg > 27
	return nil, nil, fmt.Errorf("Can't parse really long byte strings: %b", b[0])
}

func parseText(b []byte) (string, []byte, error) {
	t := b[0] & typeMask
	if t != typeText {
		return "", nil, fmt.Errorf("Text type was not passed in, got %b.", b[0])
	}

	length := b[0] & argsMask
	if length == 31 {
		return "", nil, errors.New("Can't handle long strings.")
	}

	return string(b[1 : length+1]), b[length+1:], nil
}

func parseArray(b []byte) ([]interface{}, []byte, error) {
	if (b[0] & typeMask) != typeArray {
		return nil, nil, fmt.Errorf("Type is not an array: %b", b[0])
	}

	length := int(b[0] & argsMask)
	if length == 31 {
		return nil, nil, errors.New("Can't handle long arrays.")
	}

	arr := make([]interface{}, 0)
	remaining := b[1:]
	var item interface{}
	var err error
	for i := 0; i < length; i++ {
		item, remaining, err = decodeCBOR(remaining)
		if err != nil {
			return nil, nil, err
		}
		arr = append(arr, item)
	}
	return arr, remaining, nil
}

type pair struct {
	key, value interface{}
}

func parseMap(b []byte) ([]pair, []byte, error) {
	if (b[0] & typeMask) != typeMap {
		return nil, nil, fmt.Errorf("Type is not a map: %b", b[0])
	}

	length := int(b[0] & argsMask)
	if length == 31 {
		return nil, nil, errors.New("Don't know how to handle large maps.")
	}

	m := make([]pair, 0)
	remaining := b[1:]
	var key, val interface{}
	var err error
	for i := 0; i < length; i++ {
		key, remaining, err = decodeCBOR(remaining)
		if err != nil {
			return nil, nil, fmt.Errorf("Error parsing map key: %w", err)
		}

		val, remaining, err = decodeCBOR(remaining)
		if err != nil {
			return nil, nil, fmt.Errorf("Error parsing map value: %w", err)
		}

		p := pair{key, val}
		m = append(m, p)
	}
	return m, remaining, nil
}
