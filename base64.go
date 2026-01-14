package virtualwebauthn

import (
	"encoding/json"
	"errors"
)

// FlexibleBase64 is a string type that can unmarshal from either:
// - A plain base64url string: "dGVzdA"
// - A tagged object: {"$b64u": "dGVzdA"}
//
// This allows the library to work with backends that use tagged binary
// formats for JSON serialization, such as those used by wwWallet.
type FlexibleBase64 string

// UnmarshalJSON implements json.Unmarshaler for FlexibleBase64.
// It accepts both plain strings and tagged objects with $b64u key.
func (f *FlexibleBase64) UnmarshalJSON(data []byte) error {
	// Try plain string first (most common case)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = FlexibleBase64(s)
		return nil
	}

	// Try tagged object {"$b64u": "..."}
	var tagged struct {
		B64U string `json:"$b64u"`
	}
	if err := json.Unmarshal(data, &tagged); err == nil && tagged.B64U != "" {
		*f = FlexibleBase64(tagged.B64U)
		return nil
	}

	return errors.New("invalid base64 format: expected string or {\"$b64u\": \"...\"}")
}

// String returns the underlying base64url string value.
func (f FlexibleBase64) String() string {
	return string(f)
}
