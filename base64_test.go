package virtualwebauthn

import (
	"encoding/json"
	"testing"
)

func TestFlexibleBase64_PlainString(t *testing.T) {
	jsonStr := `"dGVzdC1jaGFsbGVuZ2U"`

	var f FlexibleBase64
	err := json.Unmarshal([]byte(jsonStr), &f)
	if err != nil {
		t.Fatalf("Failed to unmarshal plain string: %v", err)
	}

	if f.String() != "dGVzdC1jaGFsbGVuZ2U" {
		t.Errorf("Expected 'dGVzdC1jaGFsbGVuZ2U', got '%s'", f.String())
	}
}

func TestFlexibleBase64_TaggedObject(t *testing.T) {
	jsonStr := `{"$b64u": "dGVzdC1jaGFsbGVuZ2U"}`

	var f FlexibleBase64
	err := json.Unmarshal([]byte(jsonStr), &f)
	if err != nil {
		t.Fatalf("Failed to unmarshal tagged object: %v", err)
	}

	if f.String() != "dGVzdC1jaGFsbGVuZ2U" {
		t.Errorf("Expected 'dGVzdC1jaGFsbGVuZ2U', got '%s'", f.String())
	}
}

func TestFlexibleBase64_InStruct(t *testing.T) {
	type TestStruct struct {
		Challenge FlexibleBase64 `json:"challenge"`
		Name      string         `json:"name"`
	}

	// Test with plain string
	plainJSON := `{"challenge": "YWJj", "name": "test"}`
	var plain TestStruct
	if err := json.Unmarshal([]byte(plainJSON), &plain); err != nil {
		t.Fatalf("Failed to unmarshal struct with plain string: %v", err)
	}
	if plain.Challenge.String() != "YWJj" {
		t.Errorf("Expected 'YWJj', got '%s'", plain.Challenge.String())
	}

	// Test with tagged object
	taggedJSON := `{"challenge": {"$b64u": "eHl6"}, "name": "test"}`
	var tagged TestStruct
	if err := json.Unmarshal([]byte(taggedJSON), &tagged); err != nil {
		t.Fatalf("Failed to unmarshal struct with tagged object: %v", err)
	}
	if tagged.Challenge.String() != "eHl6" {
		t.Errorf("Expected 'eHl6', got '%s'", tagged.Challenge.String())
	}
}

func TestParseAttestationOptions_TaggedBinary(t *testing.T) {
	// This is what wwWallet backend sends (tagged binary format)
	optionsJSON := `{
		"publicKey": {
			"challenge": {"$b64u": "dGVzdC1jaGFsbGVuZ2U"},
			"rp": {"id": "example.com", "name": "Example"},
			"user": {
				"id": {"$b64u": "dXNlci1pZA"},
				"name": "testuser",
				"displayName": "Test User"
			}
		}
	}`

	options, err := ParseAttestationOptions(optionsJSON)
	if err != nil {
		t.Fatalf("Failed to parse attestation options with tagged binary: %v", err)
	}

	if string(options.Challenge) != "test-challenge" {
		t.Errorf("Expected challenge 'test-challenge', got '%s'", string(options.Challenge))
	}

	if options.UserID != "user-id" {
		t.Errorf("Expected user ID 'user-id', got '%s'", options.UserID)
	}

	if options.RelyingPartyID != "example.com" {
		t.Errorf("Expected RP ID 'example.com', got '%s'", options.RelyingPartyID)
	}
}

func TestParseAttestationOptions_PlainBase64(t *testing.T) {
	// Standard WebAuthn format (plain base64url strings)
	optionsJSON := `{
		"publicKey": {
			"challenge": "dGVzdC1jaGFsbGVuZ2U",
			"rp": {"id": "example.com", "name": "Example"},
			"user": {
				"id": "dXNlci1pZA",
				"name": "testuser",
				"displayName": "Test User"
			}
		}
	}`

	options, err := ParseAttestationOptions(optionsJSON)
	if err != nil {
		t.Fatalf("Failed to parse attestation options with plain base64: %v", err)
	}

	if string(options.Challenge) != "test-challenge" {
		t.Errorf("Expected challenge 'test-challenge', got '%s'", string(options.Challenge))
	}

	if options.UserID != "user-id" {
		t.Errorf("Expected user ID 'user-id', got '%s'", options.UserID)
	}
}

func TestParseAssertionOptions_TaggedBinary(t *testing.T) {
	// Tagged binary format
	optionsJSON := `{
		"publicKey": {
			"challenge": {"$b64u": "bG9naW4tY2hhbGxlbmdl"},
			"rpId": "example.com",
			"allowCredentials": [
				{"type": "public-key", "id": {"$b64u": "Y3JlZC1pZA"}}
			]
		}
	}`

	options, err := ParseAssertionOptions(optionsJSON)
	if err != nil {
		t.Fatalf("Failed to parse assertion options with tagged binary: %v", err)
	}

	if string(options.Challenge) != "login-challenge" {
		t.Errorf("Expected challenge 'login-challenge', got '%s'", string(options.Challenge))
	}

	if options.RelyingPartyID != "example.com" {
		t.Errorf("Expected RP ID 'example.com', got '%s'", options.RelyingPartyID)
	}

	if len(options.AllowCredentials) != 1 {
		t.Fatalf("Expected 1 allowed credential, got %d", len(options.AllowCredentials))
	}

	if options.AllowCredentials[0] != "Y3JlZC1pZA" {
		t.Errorf("Expected credential ID 'Y3JlZC1pZA', got '%s'", options.AllowCredentials[0])
	}
}

func TestParseAssertionOptions_PlainBase64(t *testing.T) {
	// Standard WebAuthn format
	optionsJSON := `{
		"publicKey": {
			"challenge": "bG9naW4tY2hhbGxlbmdl",
			"rpId": "example.com",
			"allowCredentials": [
				{"type": "public-key", "id": "Y3JlZC1pZA"}
			]
		}
	}`

	options, err := ParseAssertionOptions(optionsJSON)
	if err != nil {
		t.Fatalf("Failed to parse assertion options with plain base64: %v", err)
	}

	if string(options.Challenge) != "login-challenge" {
		t.Errorf("Expected challenge 'login-challenge', got '%s'", string(options.Challenge))
	}
}
