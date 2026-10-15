// 🤖 ross

package authenticator

import (
	"encoding/hex"
	"testing"
)

// iOS 27 is the first release to set the extension data (ED) flag and append a
// CBOR map of extensions after the attested credential data.
const authDataIOS27 = "1f7b4b0357b1db854d8003b7d94deabca73f6c0b23a078fe3d06f5d520960580" +
	"c000000000617070617474657374000000000000000020f2ef42ac011bc943e2" +
	"b899fe12caef575be176a1e1ee0f943282dbd3a3d32e1aa50102032620012158" +
	"20236e041fa08126c073ea4a0742c1f0d455c6c2d3a127d56bc760935204a762" +
	"a6225820867dc48bad1faaf57eb68bae0ee06e84578ecfce3564cd0e53544c97" +
	"b13095d2a2776170706c655f62756e646c655f76657273696f6e5f3031633333" +
	"38781c6170706c655f76616c69646174696f6e5f63617465676f72795f303144" +
	"02000000"

// iOS 16, which sets only the attested credential data (AT) flag.
const authDataIOS16 = "19a6b2ba2d7600e4c0f7aca6720d6c212eb7d48f2b98ce56cbb25fc97fec07a2" +
	"4000000000617070617474657374646576656c6f7000209c6ae94e31dda72ea2" +
	"8e65633c847ef29c7687c7ea526bdf5b66938cf01e6d10a50102032620012158" +
	"201e3e1fe6aabb63075a7a9e2cca4ebe46cc7ef98e809eddceea482a1a46ca8d" +
	"8622582086f27618a8b3f728888c3c6934ff4534628923dc45c4422effaacda7" +
	"329a4653"

func TestUnmarshalAuthenticatorData(t *testing.T) {
	for _, tc := range []struct {
		name          string
		authData      string
		wantExtension bool
	}{
		{name: "ios-16", authData: authDataIOS16, wantExtension: false},
		{name: "ios-27-extension-data", authData: authDataIOS27, wantExtension: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.authData)
			if err != nil {
				t.Fatal(err)
			}

			var a AuthenticatorData
			if err := a.Unmarshal(raw); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			if got := a.Flags.HasAttestedCredentialData(); !got {
				t.Error("expected attested credential data")
			}
			if got := a.Flags.HasExtensions(); got != tc.wantExtension {
				t.Errorf("HasExtensions() = %v, want %v", got, tc.wantExtension)
			}
			if got := len(a.ExtData) > 0; got != tc.wantExtension {
				t.Errorf("len(ExtData) > 0 = %v, want %v", got, tc.wantExtension)
			}
			if len(a.AttData.CredentialID) != 32 {
				t.Errorf("CredentialID is %d bytes, want 32", len(a.AttData.CredentialID))
			}
			if len(a.AttData.CredentialPublicKey) == 0 {
				t.Error("expected a credential public key")
			}
		})
	}
}

// An assertion's authenticator data is just the fixed-length header. Apple sets
// the attested credential data flag on it anyway, so the flag cannot be trusted.
func TestUnmarshalAssertionAuthenticatorData(t *testing.T) {
	raw, err := hex.DecodeString(authDataIOS27)
	if err != nil {
		t.Fatal(err)
	}

	var a AuthenticatorData
	if err := a.Unmarshal(raw[:minAuthDataLength]); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(a.AttData.CredentialID) != 0 || len(a.ExtData) != 0 {
		t.Error("expected no attested credential data and no extensions")
	}
}

// Trailing bytes that are neither attested credential data nor extensions are
// still an error, and a truncated record must not panic.
func TestUnmarshalAuthenticatorDataErrors(t *testing.T) {
	raw, err := hex.DecodeString(authDataIOS16)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		authData []byte
	}{
		{name: "trailing-garbage", authData: append(append([]byte{}, raw...), 0x00)},
		{name: "truncated-attested-data", authData: raw[:minAuthDataLength+8]},
		{name: "truncated-credential-id", authData: raw[:minAuthDataLength+40]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a AuthenticatorData
			if err := a.Unmarshal(tc.authData); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
