// Copyright 2023 Jesus Ruiz. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.

package jpath

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/alastria/isbe-onboarding/internal/errl"
)

// GetMap returns a map[string]any according to a dotted path or default or map[string]any.
func GetMap(data any, path string, defaults ...map[string]any) map[string]any {
	value, err := GetMapStrict(data, path)
	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}

	return map[string]any{}
}

func SetMap(data any, path string, key string, value any) error {
	m, err := GetMapStrict(data, path)
	if err != nil {
		return err
	}

	m[key] = value
	return nil
}

// GetMapStrict returns a map[string]any according to a dotted path.
func GetMapStrict(data any, path string) (map[string]any, error) {
	n, err := Get(data, path)
	if err != nil {
		return nil, err
	}

	if value, ok := n.(map[string]any); ok {
		return value, nil
	}

	return nil, typeMismatch("map[string]any", n)
}

// GetString returns a string according to a dotted path or default or "".
func GetString(data any, path string, defaults ...string) string {
	value, err := GetStringStrict(data, path)
	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}

	return ""
}

// GetStringStrict returns a string according to a dotted path.
func GetStringStrict(data any, path string) (string, error) {
	n, err := Get(data, path)
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

// GetBool returns a bool according to a dotted path or default value or false.
func GetBool(data any, path string, defaults ...bool) bool {
	value, err := GetBoolStrict(data, path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return false
}

// GetBoolStrict returns a bool according to a dotted path.
func GetBoolStrict(data any, path string) (bool, error) {
	n, err := Get(data, path)
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

// GetFloat64 returns a float64 according to a dotted path or default value or 0.
func GetFloat64(data any, path string, defaults ...float64) float64 {
	value, err := GetFloat64Strict(data, path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return float64(0)
}

// GetFloat64Strict returns a float64 according to a dotted path.
func GetFloat64Strict(data any, path string) (float64, error) {
	n, err := Get(data, path)
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

// GetInt returns an int according to a dotted path or default value or 0.
func GetInt(data any, path string, defaults ...int) int {
	value, err := GetIntStrict(data, path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return 0
}

// GetIntStrict returns an int according to a dotted path.
func GetIntStrict(data any, path string) (int, error) {
	n, err := Get(data, path)
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

// GetList returns a []any according to a dotted path or defaults or []any.
func GetList(data any, path string, defaults ...[]any) []any {
	value, err := GetListStrict(data, path)

	if err == nil {
		return value
	}

	for _, def := range defaults {
		return def
	}
	return make([]any, 0)
}

// GetListStrict returns a []any according to a dotted path.
func GetListStrict(data any, path string) ([]any, error) {
	n, err := Get(data, path)
	if err != nil {
		return nil, err
	}
	if value, ok := n.([]any); ok {
		return value, nil
	}
	return nil, typeMismatch("[]any", n)
}

// GetListString is for the very common case of a list of strings
func GetListString(data any, path string, defaults ...[]string) []string {
	value, err := GetListStrict(data, path)

	if err == nil {
		return ToListString(value)
	}

	for _, def := range defaults {
		return def
	}
	return make([]string, 0)
}

func ToListString(in []any) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = (in[i]).(string)
	}
	return out
}

// Get returns a child of the given value according to a dotted path.
// The source data must be either map[string]any or []any
func Get(src any, path string) (any, error) {

	// Quick short-circuit
	if path == "" || path == "." {
		return src, nil
	}

	// Two consecutive dots is an error
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("invalid path %q: contains '..'", path)
	}

	parts := strings.Split(path, ".")

	// Get the value.
	for pos, pathComponent := range parts {

		switch c := src.(type) {

		case []any:
			// If data is an array, the path component must be an integer (base 10) to index the array,
			// or an asterisk '*'.
			// The asterisk means that we have to iterate the array to find the element

			// First, process the '*'
			if pathComponent == "*" {
				for _, el := range c {
					v, err := Get(el, strings.Join(parts[pos+1:], "."))
					if err == nil {
						return v, nil
					}
				}
				return nil, errl.Errorf("error searching array")
			}

			index, err := strconv.ParseInt(pathComponent, 10, 0)
			if err != nil {
				return nil, fmt.Errorf("jpath.Get: invalid list index at %q",
					strings.Join(parts[:pos+1], "."))
			}
			if int(index) < len(c) {
				// Update src to be the indexed element of the array
				src = c[index]
			} else {
				return nil, fmt.Errorf(
					"jpath.Get: index out of range at %q: list has only %v items",
					strings.Join(parts[:pos+1], "."), len(c))
			}

		case map[string]any:
			// If data is a map, try to get the corresponding element
			if value, ok := c[pathComponent]; ok {
				src = value
			} else {
				return nil, fmt.Errorf("jpath.Get: nonexistent map key at %q",
					strings.Join(parts[:pos+1], "."))
			}

		default:

			// For other types, use reflection
			srcKind := reflect.TypeOf(src).Kind()
			srcValue := reflect.ValueOf(src)

			// This is a type backed by a Map
			if srcKind == reflect.Map {
				newValue := srcValue.MapIndex(reflect.ValueOf(pathComponent))

				if !newValue.IsValid() || newValue.IsZero() {
					return nil, fmt.Errorf("jpath.Get: nonexistent map key at %q",
						strings.Join(parts[:pos+1], "."))
				}
				src = newValue.Interface()

				continue
			}

			// And this is a Slice
			if srcKind == reflect.Slice {
				index64, err := strconv.ParseInt(pathComponent, 10, 0)
				if err != nil {
					return nil, fmt.Errorf("jpath.Get: invalid list index at %q",
						strings.Join(parts[:pos+1], "."))
				}
				index := int(index64)
				if index < 0 {
					return nil, fmt.Errorf(
						"jpath.Get: index out of range at %q: index is negative: %v",
						strings.Join(parts[:pos+1], "."), index)
				}
				if index >= srcValue.Len() {
					return nil, fmt.Errorf(
						"jpath.Get: index out of range at %q: list has only %v items",
						strings.Join(parts[:pos+1], "."), srcValue.Len())
				}
				// Update src to be the indexed element of the array
				newValue := srcValue.Index(index)
				src = newValue.Interface()

				continue
			}

			return nil, fmt.Errorf(
				"jpath.Get: invalid type at %q: expected []any or map[string]any; got %T",
				strings.Join(parts[:pos+1], "."), src)
		}
	}

	return src, nil
}
