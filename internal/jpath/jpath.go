// Copyright 2023 Jesus Ruiz. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.

// Package jpath provides a wrapper for traversing and accessing JSON/YAML structures using dot notation.
package jpath

import (
	"fmt"
	"os"
	"strconv"

	"github.com/goccy/go-json"
	"github.com/goccy/go-yaml"
)

// YAML represents a complex internal YAML structure with convenient access methods,
// using dotted path syntax
type YAML struct {
	data any
}

// *************************************************************
// Utility functions to parse JSON and YAML files
// *************************************************************

// ParseJson reads a JSON configuration from the given string.
func ParseJson(src string) (*YAML, error) {
	return parseJson([]byte(src))
}

// ParseJsonFile reads a JSON configuration from the given filename.
func ParseJsonFile(filename string) (*YAML, error) {
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parseJson(src)
}

// parseJson performs the real JSON parsing.
func parseJson(src []byte) (*YAML, error) {
	var out any
	var err error
	if err = json.Unmarshal(src, &out); err != nil {
		return nil, err
	}
	return &YAML{data: out}, nil
}

// ParseYamlBytes reads a YAML configuration from the given []byte.
func ParseYamlBytes(src []byte) (*YAML, error) {
	return parseYaml(src)
}

// ParseYaml reads a YAML configuration from the given string.
func ParseYaml(src string) (*YAML, error) {
	return parseYaml([]byte(src))
}

// ParseYamlFile reads a YAML configuration from the given filename.
func ParseYamlFile(filename string) (*YAML, error) {
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parseYaml(src)
}

// parseYaml performs the real YAML parsing.
func parseYaml(src []byte) (*YAML, error) {
	var out any
	var err error
	if err = yaml.Unmarshal(src, &out); err != nil {
		return nil, err
	}
	return &YAML{data: out}, nil
}

func New(data any) *YAML {
	return &YAML{data: data}
}

func (y *YAML) Data() any {
	return y.data
}

// Get returns a nested element according to a dotted path.
func (y *YAML) Get(path string) (*YAML, error) {
	n, err := Get(y.data, path)
	if err != nil {
		return nil, err
	}
	return &YAML{data: n}, nil
}

// bool returns a bool according to a dotted path.
func (y *YAML) bool(path string) (bool, error) {
	n, err := Get(y.data, path)
	if err != nil {
		return false, err
	}
	switch n := n.(type) {
	case bool:
		return n, nil
	case string:
		return strconv.ParseBool(n)
	}
	return false, typeMismatch("bool or string", n)
}

// Bool returns a bool according to a dotted path or default value or false.
func (y *YAML) Bool(path string, defaults ...bool) bool {
	value, err := y.bool(path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return false
}

// float64 returns a float64 according to a dotted path.
func (y *YAML) float64(path string) (float64, error) {
	n, err := Get(y.data, path)
	if err != nil {
		return 0, err
	}
	switch n := n.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	case string:
		return strconv.ParseFloat(n, 64)
	}
	return 0, typeMismatch("float64, int or string", n)
}

// Float64 returns a float64 according to a dotted path or default value or 0.
func (y *YAML) Float64(path string, defaults ...float64) float64 {
	value, err := y.float64(path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return float64(0)
}

// int returns an int according to a dotted path.
func (y *YAML) int(path string) (int, error) {
	n, err := Get(y.data, path)
	if err != nil {
		return 0, err
	}
	switch n := n.(type) {
	case float64:
		// encoding/json unmarshals numbers into floats, so we compare
		// the string representation to see if we can return an int.
		if i := int(n); fmt.Sprint(i) == fmt.Sprint(n) {
			return i, nil
		} else {
			return 0, fmt.Errorf("value can't be converted to int: %v", n)
		}
	case int:
		return n, nil
	case string:
		if v, err := strconv.ParseInt(n, 10, 0); err == nil {
			return int(v), nil
		} else {
			return 0, err
		}
	}
	return 0, typeMismatch("float64, int or string", n)
}

// Int returns an int according to a dotted path or default value or 0.
func (y *YAML) Int(path string, defaults ...int) int {
	value, err := y.int(path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return 0
}

// list returns a []any according to a dotted path.
func (y *YAML) list(path string) ([]any, error) {
	n, err := Get(y.data, path)
	if err != nil {
		return nil, err
	}
	if value, ok := n.([]any); ok {
		return value, nil
	}
	return nil, typeMismatch("[]any", n)
}

// List returns a []any according to a dotted path or defaults or []any.
func (y *YAML) List(path string, defaults ...[]any) []any {
	value, err := y.list(path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return make([]any, 0)
}

// ListString is for the very common case of a list of strings
func (y *YAML) ListString(path string, defaults ...[]string) []string {
	value, err := y.list(path)

	if err == nil {
		return ToListString(value)
	}

	for _, def := range defaults {
		return def
	}
	return make([]string, 0)
}

// map_strict returns a map[string]any according to a dotted path.
func (y *YAML) map_strict(path string) (map[string]any, error) {
	n, err := Get(y.data, path)
	if err != nil {
		return nil, err
	}
	if value, ok := n.(map[string]any); ok {
		return value, nil
	}
	return nil, typeMismatch("map[string]any", n)
}

// Map returns a map[string]any according to a dotted path or default or map[string]any.
func (y *YAML) Map(path string, defaults ...map[string]any) map[string]any {
	value, err := y.map_strict(path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return map[string]any{}
}

// string_strict returns a string according to a dotted path.
func (y *YAML) string_strict(path string) (string, error) {
	n, err := Get(y.data, path)
	if err != nil {
		return "", err
	}
	switch n := n.(type) {
	case bool, float64, int:
		return fmt.Sprint(n), nil
	case string:
		return n, nil
	}
	return "", typeMismatch("bool, float64, int or string", n)
}

// String returns a string according to a dotted path or default or "".
func (y *YAML) String(path string, defaults ...string) string {
	value, err := y.string_strict(path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return ""
}

// typeMismatch returns an error for an expected type.
func typeMismatch(expected string, got any) error {
	return fmt.Errorf("type mismatch: expected %s; got %T", expected, got)
}
