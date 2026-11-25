package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParseDocument(f *testing.F) {
	seeds := []string{
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"],"Condition":{"Bool":{"aws:SecureTransport":true}}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
		`%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D`,
		`{}`,
		`{"Statement":null}`,
		`{"Statement":[{"Condition":{"NumericLessThan":{"k":123}}}]}`,
		`not json at all`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, input string) {
		parsed, err := ParseDocument(input)
		if err == nil && parsed != nil {
			_, _ = GuardrailCapsAdminWildcard(parsed)
		}
	})
}

func FuzzParseTrustPolicy(f *testing.F) {
	seeds := []string{
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["bedrock.amazonaws.com","lambda.amazonaws.com"]},"Action":"sts:AssumeRole"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:org/*:*"}}}]}`,
		`{"Statement":{"Effect":"Deny","Principal":{"AWS":"123456789012"}}}`,
		`{}`,
		`broken`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, input string) {
		principals, err := ParseTrustPolicy(input)
		if err == nil {
			for _, p := range principals {
				_ = ExtractAccountID(p.Value)
			}
		}
	})
}

func TestLoadSCPFileAndGuardrailCapsAdminWildcard(t *testing.T) {
	dir := t.TempDir()

	// 1. Single restrictive SCP document (caps admin).
	singlePath := filepath.Join(dir, "single.json")
	if err := os.WriteFile(singlePath, []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	single, err := LoadSCPFile(singlePath)
	if err != nil || len(single) != 1 {
		t.Fatalf("LoadSCPFile(single) = (%v, %v)", single, err)
	}
	if capped, _ := GuardrailCapsAdminWildcard(single[0].Parsed); !capped {
		t.Errorf("expected SCP denying iam:* to cap admin wildcard")
	}

	// 2. AWS Organizations wrapper with FullAWSAccess (does NOT cap admin).
	orgPath := filepath.Join(dir, "org.json")
	orgJSON := `{"Policies":[{"Name":"FullAWSAccess","Content":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}]}`
	if err := os.WriteFile(orgPath, []byte(orgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	orgPols, err := LoadSCPFile(orgPath)
	if err != nil || len(orgPols) != 1 || orgPols[0].Name != "FullAWSAccess" {
		t.Fatalf("LoadSCPFile(org) = (%v, %v)", orgPols, err)
	}
	if capped, why := GuardrailCapsAdminWildcard(orgPols[0].Parsed); capped {
		t.Errorf("FullAWSAccess SCP must NOT cap admin wildcard (got why=%q)", why)
	}

	// 3. Array of SCP documents where one restricts actions to sts:GetCallerIdentity.
	arrPath := filepath.Join(dir, "arr.json")
	arrJSON := `[{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}]`
	if err := os.WriteFile(arrPath, []byte(arrJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	arrPols, err := LoadSCPFile(arrPath)
	if err != nil || len(arrPols) != 1 {
		t.Fatalf("LoadSCPFile(arr) = (%v, %v)", arrPols, err)
	}
	if capped, _ := GuardrailCapsAdminWildcard(arrPols[0].Parsed); !capped {
		t.Errorf("expected sts-only policy to cap admin wildcard")
	}
}
