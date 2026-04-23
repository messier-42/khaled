// Package config provides an abstract representation for structured
// configuration objects.
//
// In particular, this package is designed to allow plugins to add
// config items without having to change this package.
package config

import (
	"context"
	"errors"
	"fmt"
)

// Value is an arbitrary configuration value.
type Value any

// Map is a configuration node mapping keys to values.
type Map map[string]Value

// Array is a configuration node representing a sequence of values.
type Array []Value

// Snapshot is a loaded configuration instance.
type Snapshot struct {
	// The root of a Snapshot is always a Map.
	Root Map
}

// Source provides a way of loading a configuration snapshot from some
// unspecified backing store.
type Source interface {
	Load(ctx context.Context) (Snapshot, error)
}

// NewSnapshot normalizes an arbitrary decoded object graph into a configuration snapshot.
func NewSnapshot(raw any) (Snapshot, error) {
	root, ok := Normalize(raw).(Map)
	if !ok {
		return Snapshot{}, errors.New("config root must be an object")
	}

	return Snapshot{Root: root}, nil
}

// Normalize converts decoded YAML/CBOR values into khaled-native configuration values.
func Normalize(value any) Value {
	switch typed := value.(type) {
	case Map:
		out := make(Map, len(typed))
		for key, child := range typed {
			out[key] = Normalize(child)
		}
		return out
	case map[string]any:
		out := make(Map, len(typed))
		for key, child := range typed {
			out[key] = Normalize(child)
		}
		return out
	case map[any]any:
		out := make(Map, len(typed))
		for key, child := range typed {
			out[fmt.Sprint(key)] = Normalize(child)
		}
		return out
	case Array:
		out := make(Array, len(typed))
		for i, child := range typed {
			out[i] = Normalize(child)
		}
		return out
	case []any:
		out := make(Array, len(typed))
		for i, child := range typed {
			out[i] = Normalize(child)
		}
		return out
	case []string:
		out := make(Array, len(typed))
		for i, child := range typed {
			out[i] = child
		}
		return out
	case []int:
		out := make(Array, len(typed))
		for i, child := range typed {
			out[i] = int64(child)
		}
		return out
	case int:
		return int64(typed)
	case int8:
		return int64(typed)
	case int16:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint:
		return uint64(typed)
	case uint8:
		return uint64(typed)
	case uint16:
		return uint64(typed)
	case uint32:
		return uint64(typed)
	case uint64:
		return typed
	case float32:
		return float64(typed)
	default:
		return typed
	}
}

func (o Map) Get(key string) (Value, bool) {
	value, ok := o[key]
	return value, ok
}

func (o Map) GetMap(key string) (Map, bool) {
	value, ok := o[key]
	if !ok {
		return nil, false
	}

	object, ok := value.(Map)
	return object, ok
}

func (o Map) GetArray(key string) (Array, bool) {
	value, ok := o[key]
	if !ok {
		return nil, false
	}

	list, ok := value.(Array)
	return list, ok
}

func (o Map) GetString(key string) (string, bool) {
	value, ok := o[key]
	if !ok {
		return "", false
	}

	text, ok := value.(string)
	return text, ok
}

func (o Map) GetBool(key string) (bool, bool) {
	value, ok := o[key]
	if !ok {
		return false, false
	}

	flag, ok := value.(bool)
	return flag, ok
}

func (l Array) Index(index int) (Value, bool) {
	if index < 0 || index >= len(l) {
		return 0, false
	}

	v := l[index]
	return v, true
}
