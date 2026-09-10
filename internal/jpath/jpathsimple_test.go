// Copyright 2023 Jesus Ruiz. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.

package jpath

import (
	"reflect"
	"testing"
)

func sampleOrganization() map[string]any {
	return map[string]any{
		"@type":         "organization",
		"contactMedium": nil,
		"externalReference": []any{
			map[string]any{
				"externalReferenceType": "idm_id",
				"name":                  "VATES-12345678J",
			},
		},
		"href":          "urn:ngsi-ld:organization:VATES-12345678J",
		"id":            "urn:ngsi-ld:organization:VATES-12345678J",
		"isLegalEntity": true,
		"lastUpdate":    "2025-10-02T06:20:14.306557796Z",
		"name":          "GoodAir Foundation",
		"organizationIdentification": []any{
			map[string]any{
				"@type":              "organizationIdentification",
				"identificationId":   "did:elsi:VATES-12345678J",
				"identificationType": "did:elsi",
				"issuingAuthority":   "eIDAS",
			},
		},
		"tradingName": "GoodAir Foundation",
		"version":     "1.0",
	}
}

func TestGet(t *testing.T) {
	data := sampleOrganization()

	tests := []struct {
		name    string
		path    string
		want    any
		wantErr bool
	}{
		{
			name:    "simple key",
			path:    "@type",
			want:    "organization",
			wantErr: false,
		},
		{
			name:    "nested array index",
			path:    "externalReference.0.name",
			want:    "VATES-12345678J",
			wantErr: false,
		},
		{
			name:    "nested array wildcard",
			path:    "externalReference.*.name",
			want:    "VATES-12345678J",
			wantErr: false,
		},
		{
			name:    "organizationIdentification.*.identificationId",
			path:    "organizationIdentification.*.identificationId",
			want:    "did:elsi:VATES-12345678J",
			wantErr: false,
		},
		{
			name:    "nonexistent key",
			path:    "foo.bar",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "out of range index",
			path:    "externalReference.10.name",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "consecutive dots error",
			path:    "externalReference..name",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty path returns root",
			path:    "",
			want:    data,
			wantErr: false,
		},
		{
			name:    "dot path returns root",
			path:    ".",
			want:    data,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Get(data, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// For root, compare by reference
				if tt.path == "" || tt.path == "." {
					if !reflect.DeepEqual(got, data) {
						t.Errorf("Get(%q) = %v, want root data", tt.path, got)
					}
				} else if got != tt.want {
					t.Errorf("Get(%q) = %v, want %v", tt.path, got, tt.want)
				}
			}
		})
	}
}
