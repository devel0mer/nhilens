package policy

import (
	"testing"

	"github.com/devel0mer/nhilens/internal/model"
)

func TestEvaluateEffectiveActionBoundarySCPAndDeny(t *testing.T) {
	baseIdent := func(policyJSON, boundaryJSON string) *model.Identity {
		id := &model.Identity{
			Type:                   model.TypeRole,
			Name:                   "test-role",
			ARN:                    "arn:aws:iam::123456789012:role/test-role",
			PermissionsBoundaryARN: "arn:aws:iam::123456789012:policy/test-boundary",
			PermissionsBoundaryDoc: boundaryJSON,
			Policies: []model.PolicyAttachment{
				{Name: "inline", Kind: "inline", RawDocument: policyJSON},
			},
		}
		ParseAndSummarize(id)
		return id
	}

	// 1. Identity explicit Deny blocks an otherwise allowed action.
	idDeny := baseIdent(
		`{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":"secretsmanager:*","Resource":"*"},
			{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}
		]}`,
		"",
	)
	dec := EvaluateEffectiveAction(idDeny, nil, "secretsmanager:getsecretvalue", "*")
	if dec.Allowed || dec.BlockedBy != "identity_deny" {
		t.Errorf("expected identity_deny block, got %+v", dec)
	}
	decPut := EvaluateEffectiveAction(idDeny, nil, "secretsmanager:putsecretvalue", "*")
	if !decPut.Allowed {
		t.Errorf("expected secretsmanager:PutSecretValue still allowed, got %+v", decPut)
	}

	// 2. Permissions boundary blocks iam:PassRole while allowing s3:GetObject.
	idBounded := baseIdent(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","s3:GetObject"],"Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
	)
	if d := EvaluateEffectiveAction(idBounded, nil, "iam:passrole", "*"); d.Allowed || d.BlockedBy != "permissions_boundary" {
		t.Errorf("expected permissions_boundary to block iam:PassRole, got %+v", d)
	}
	if d := EvaluateEffectiveAction(idBounded, nil, "s3:getobject", "arn:aws:s3:::bucket/obj"); !d.Allowed {
		t.Errorf("expected s3:GetObject allowed through boundary, got %+v", d)
	}

	// 3. SCP denies kms:Decrypt while allowing other actions (NotAction Deny or explicit Deny).
	scpParsed, err := ParseDocument(`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}
	]}`)
	if err != nil {
		t.Fatal(err)
	}
	scps := []NamedPolicy{{Name: "deny-kms-decrypt", Parsed: scpParsed}}
	idKMS := baseIdent(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*"}]}`,
		"",
	)
	if d := EvaluateEffectiveAction(idKMS, scps, "kms:decrypt", "*"); d.Allowed || d.BlockedBy != "scp:deny-kms-decrypt" {
		t.Errorf("expected SCP to block kms:Decrypt, got %+v", d)
	}
	if d := EvaluateEffectiveAction(idKMS, scps, "kms:creategrant", "*"); !d.Allowed {
		t.Errorf("expected kms:CreateGrant still allowed through SCP, got %+v", d)
	}

	// 4. Conditioned Permissions Boundary propagates Conditioned=true and ConditionKeys.
	idCondBoundary := baseIdent(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"sandbox"}}}]}`,
	)
	dCond := EvaluateEffectiveAction(idCondBoundary, nil, "secretsmanager:getsecretvalue", "*")
	if !dCond.Allowed || !dCond.Conditioned || len(dCond.ConditionKeys) != 1 || dCond.ConditionKeys[0] != "aws:ResourceTag/env" {
		t.Errorf("expected conditioned allow with aws:ResourceTag/env, got %+v", dCond)
	}

	// 5. Allow NotAction semantics: Allow NotAction:["iam:*"] allows s3:GetObject, does NOT allow iam:AttachRolePolicy.
	idNotAction := baseIdent(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
		"",
	)
	if d := EvaluateEffectiveAction(idNotAction, nil, "s3:getobject", "*"); !d.Allowed {
		t.Errorf("expected Allow NotAction:iam:* to allow s3:GetObject, got %+v", d)
	}
	if d := EvaluateEffectiveAction(idNotAction, nil, "iam:attachrolepolicy", "*"); d.Allowed {
		t.Errorf("expected Allow NotAction:iam:* NOT to allow iam:AttachRolePolicy, got %+v", d)
	}
}
