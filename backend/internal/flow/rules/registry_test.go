// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type RegistryTestSuite struct {
	suite.Suite
}

func TestRegistryTestSuite(t *testing.T) {
	suite.Run(t, new(RegistryTestSuite))
}

// customerScope is a registration-free scope with one user type, a prompt and an extension step.
func customerScope() SignalScope {
	return SignalScope{
		FlowType: "AUTHENTICATION",
		UserTypes: []UserTypeSchema{{Name: "customer", Attributes: []SchemaAttribute{
			{Name: "email", Type: schemaTypeEmail},
			{Name: "tier", Display: "Tier", Type: schemaTypeString},
			{Name: "creditLimit", Type: schemaTypeNumber},
			{Name: "verified", Type: schemaTypeBoolean},
			{Name: "roles", Type: schemaTypeArray, ItemType: schemaTypeString},
			{Name: "password", Type: schemaTypeString, Credential: true},
			{Name: "address", Type: "object"},
			{Name: "devices", Type: schemaTypeArray, ItemType: "object"},
			{Name: "nested", Type: schemaTypeArray, ItemType: schemaTypeArray},
			{Name: "bad-name", Type: schemaTypeString},
		}}},
		Inputs: []FlowInput{
			{Identifier: "username", Type: "TEXT_INPUT"},
			{Identifier: "email", Type: inputTypeEmail},
			{Identifier: "age", Type: inputTypeNumber},
			{Identifier: "password", Type: inputTypePassword},
			{Identifier: "otp", Type: inputTypeOTP},
			{Identifier: "pin", Type: "TEXT_INPUT", Credential: true},
		},
		ExtensionSteps: []ExtensionStep{{
			NodeID: "age_service", ResponseKeys: []string{"age", "band"},
			Outputs: map[string]ExtensionOutput{"age": {Display: "User age", Comparator: "number", Sensitivity: "pii"}},
		}},
	}
}

// signals builds the registry of a scope and requires no diagnostics.
func (s *RegistryTestSuite) signals(scope SignalScope) SignalRegistryInterface {
	r, diagnostics := Initialize().Signals(scope)
	s.Require().Empty(diagnostics)
	return r
}

func (s *RegistryTestSuite) TestBuiltInSignals() {
	r := s.signals(SignalScope{})

	groups, ok := r.Lookup("user.groups")
	s.Require().True(ok)
	s.Equal(SignalLayerBuiltIn, groups.Layer)
	s.True(groups.Multi)
	s.Equal(CostStore, groups.CostClass)
	s.Equal(TrustDirectory, groups.Trust)
	s.Equal(SignalUserID, groups.With)
	s.True(groups.AccountData)

	authTime, _ := r.Lookup(SignalSessionAuthTime)
	s.Equal(ComparatorInstant, authTime.Comparator)
	s.Equal(ProducerExecutor, authTime.ProducedBy)

	authenticated, _ := r.Lookup(SignalUserAuthenticated)
	s.Equal(ComparatorBoolean, authenticated.Comparator)
	s.Empty(authenticated.With, "authentication is produced on its own, not with the user")

	flowType, _ := r.Lookup("flow.type")
	s.Equal(ProducerAlways, flowType.ProducedBy)
}

func (s *RegistryTestSuite) TestRequestFamilies() {
	r := s.signals(SignalScope{})

	header, ok := r.Lookup("request.header.X-Network-Zone")
	s.Require().True(ok)
	s.Equal("request.header.x-network-zone", header.Name, "header names are one signal in every case")
	s.Equal(TrustSubject, header.Trust)
	s.Equal(CostLocal, header.CostClass)
	s.False(header.Family)

	query, ok := r.Lookup("request.query.Locale")
	s.Require().True(ok)
	s.Equal("request.query.Locale", query.Name, "query parameter names match exactly")

	initial, ok := r.Lookup("request.initial.header.User-Agent")
	s.Require().True(ok)
	s.Equal("request.initial.header.user-agent", initial.Name)

	for _, name := range []string{
		"request.header.", "request.header.bad header", "request.header.ü", "request.query.a b", "request.query.",
		"request.header." + strings.Repeat("a", maxFamilySuffixLength+1), "request.cookie.session",
	} {
		_, ok := r.Lookup(name)
		s.False(ok, name)
	}
}

func (s *RegistryTestSuite) TestSchemaSignals() {
	r := s.signals(customerScope())

	email, ok := r.Lookup("user.email")
	s.Require().True(ok)
	s.Equal(SignalLayerSchema, email.Layer)
	s.Equal(ComparatorText, email.Comparator)
	s.Equal(SensitivityPII, email.Sensitivity)
	s.Equal(CostStore, email.CostClass)
	s.Equal(SignalUserID, email.With)
	s.True(email.AccountData)

	tier, _ := r.Lookup("user.tier")
	s.Equal("Tier", tier.Display)
	s.Equal(SensitivityInternal, tier.Sensitivity)
	limit, _ := r.Lookup("user.creditLimit")
	s.Equal(ComparatorNumber, limit.Comparator)
	verified, _ := r.Lookup("user.verified")
	s.Equal(ComparatorBoolean, verified.Comparator)
	roles, _ := r.Lookup("user.roles")
	s.True(roles.Multi)
	s.Equal(ComparatorText, roles.Comparator)

	for _, name := range []string{"user.password", "user.address", "user.devices", "user.nested", "user.bad-name"} {
		_, ok := r.Lookup(name)
		s.False(ok, name)
	}
}

func (s *RegistryTestSuite) TestSchemaCannotRedeclareBuiltIns() {
	r := s.signals(SignalScope{UserTypes: []UserTypeSchema{{Name: "t", Attributes: []SchemaAttribute{
		{Name: "id", Type: schemaTypeString}, {Name: "groups", Type: schemaTypeString},
	}}}})

	id, _ := r.Lookup(SignalUserID)
	s.Equal(SignalLayerBuiltIn, id.Layer)
	groups, _ := r.Lookup("user.groups")
	s.Equal(TrustDirectory, groups.Trust)
	s.True(groups.Multi)
}

func (s *RegistryTestSuite) TestUserTypesThatDisagreeLeaveTheComparatorToInference() {
	r := s.signals(SignalScope{UserTypes: []UserTypeSchema{
		{Name: "employee", Attributes: []SchemaAttribute{{Name: "code", Type: schemaTypeNumber}}},
		{Name: "contractor", Attributes: []SchemaAttribute{
			{Name: "code", Type: schemaTypeArray, ItemType: schemaTypeMobile},
		}},
	}})

	code, _ := r.Lookup("user.code")
	s.Empty(code.Comparator)
	s.True(code.Multi)
	s.Equal(SensitivityPII, code.Sensitivity)
}

func (s *RegistryTestSuite) TestInputSignals() {
	r := s.signals(customerScope())

	username, ok := r.Lookup("input.username")
	s.Require().True(ok)
	s.Equal(SignalLayerFlow, username.Layer)
	s.Equal(SignalCategoryUserCollected, username.Category)
	s.Equal(TrustSubject, username.Trust)
	s.Equal(ComparatorText, username.Comparator)
	s.Equal(ProducerInput, username.ProducedBy)
	age, _ := r.Lookup("input.age")
	s.Equal(ComparatorNumber, age.Comparator)
	email, _ := r.Lookup("input.email")
	s.Equal(SensitivityPII, email.Sensitivity)

	for _, name := range []string{"input.password", "input.otp", "input.pin"} {
		_, ok := r.Lookup(name)
		s.False(ok, name)
	}
}

func (s *RegistryTestSuite) TestAnInputOnSeveralPromptsIsOneSignal() {
	r := s.signals(SignalScope{Inputs: []FlowInput{
		{Identifier: "code", Type: inputTypeNumber}, {Identifier: "code", Type: "TEXT_INPUT"},
	}})

	code, ok := r.Lookup("input.code")
	s.True(ok)
	s.Empty(code.Comparator)

	contact, _ := s.signals(SignalScope{Inputs: []FlowInput{
		{Identifier: "contact", Type: "TEXT_INPUT"}, {Identifier: "contact", Type: inputTypeEmail},
	}}).Lookup("input.contact")
	s.Equal(SensitivityPII, contact.Sensitivity, "the more sensitive declaration wins")
}

func (s *RegistryTestSuite) TestIdentifiers() {
	cases := []struct {
		name      string
		lowerOnly bool
		valid     bool
	}{
		{"age", false, true},
		{"creditLimit", false, true},
		{"credit_limit2", true, true},
		{"creditLimit", true, false},
		{"2fa", false, false},
		{"_hidden", false, false},
		{"a-b", false, false},
		{"", false, false},
		{strings.Repeat("a", maxNameSegmentLength), false, true},
		{strings.Repeat("a", maxNameSegmentLength+1), false, false},
	}
	for _, tc := range cases {
		s.Equal(tc.valid, isIdentifier(tc.name, tc.lowerOnly), tc.name)
	}
}

func (s *RegistryTestSuite) TestExtensionSignals() {
	r := s.signals(customerScope())

	age, ok := r.Lookup("extension.age_service.age")
	s.Require().True(ok)
	s.Equal("User age", age.Display)
	s.Equal(ComparatorNumber, age.Comparator)
	s.Equal(SensitivityPII, age.Sensitivity)
	s.Equal(TrustExternal, age.Trust)
	s.Equal(SignalCategoryRuntime, age.Category)
	s.Equal(ProducerExtension, age.ProducedBy)

	band, ok := r.Lookup("extension.age_service.band")
	s.Require().True(ok)
	s.Empty(band.Comparator)
	s.Equal("band", band.Display)
}

func (s *RegistryTestSuite) TestExtensionNamesThatCannotBeSignals() {
	r := s.signals(SignalScope{ExtensionSteps: []ExtensionStep{
		{NodeID: "Age-Service", ResponseKeys: []string{"age"}},
		{NodeID: "risk", ResponseKeys: []string{"risk-score", "level"}},
		{NodeID: "all_fields"},
	}})

	for _, name := range []string{"extension.Age-Service.age", "extension.risk.risk-score"} {
		_, ok := r.Lookup(name)
		s.False(ok, name)
		code, rejected := r.rejection(name)
		s.True(rejected, name)
		s.Equal(CodeOutputName, code)
	}
	_, ok := r.Lookup("extension.risk.level")
	s.True(ok)
	_, rejected := r.rejection("extension.risk.level")
	s.False(rejected)
	for _, spec := range r.Signals() {
		s.False(strings.HasPrefix(spec.Name, "extension.all_fields."), "a step with no responseKeys produces nothing")
	}
}

func (s *RegistryTestSuite) TestOutputsProblemsAreReported() {
	r, diagnostics := Initialize().Signals(SignalScope{ExtensionSteps: []ExtensionStep{{
		NodeID: "svc", ResponseKeys: []string{"age", "level"},
		Outputs: map[string]ExtensionOutput{
			"age":     {Comparator: "scale", Sensitivity: "secret"},
			"level":   {Comparator: "colour"},
			"missing": {},
		},
	}}})

	expected := []Diagnostic{
		{NodeID: "svc", Path: "properties.outputs.missing", Code: CodeOutputNotStored, Severity: SeverityError,
			Params: map[string]string{paramName: "missing"}},
		{NodeID: "svc", Path: "properties.outputs.age.comparator", Code: CodeOutputDeclaration,
			Severity: SeverityError, Params: map[string]string{paramValue: "scale"}},
		{NodeID: "svc", Path: "properties.outputs.age.sensitivity", Code: CodeOutputDeclaration,
			Severity: SeverityError, Params: map[string]string{paramValue: "secret"}},
		{NodeID: "svc", Path: "properties.outputs.level.comparator", Code: CodeOutputDeclaration,
			Severity: SeverityError, Params: map[string]string{paramValue: "colour"}},
	}
	s.Equal(expected, diagnostics)
	age, _ := r.Lookup("extension.svc.age")
	s.Empty(age.Comparator)
	s.Equal(SensitivityInternal, age.Sensitivity)
}

func (s *RegistryTestSuite) TestFlowTypes() {
	r := newSignalRegistry(SignalScope{})
	only := SignalSpec{Name: "flow.only", FlowTypes: []string{"AUTHENTICATION"}}

	r.declare(only, "REGISTRATION")
	_, ok := r.Lookup("flow.only")
	s.False(ok)

	r.declare(only, "AUTHENTICATION")
	_, ok = r.Lookup("flow.only")
	s.True(ok)
}

func (s *RegistryTestSuite) TestEveryLayerKeepsToItsPrefixes() {
	allowed := map[SignalLayer][]string{
		SignalLayerBuiltIn: {"flow.", "application.", prefixUser, "session.", "request."},
		SignalLayerSchema:  {prefixUser},
		SignalLayerFlow:    {prefixInput, prefixExtension},
	}
	r := s.signals(customerScope())

	for _, spec := range r.Signals() {
		prefixes := allowed[spec.Layer]
		s.NotEmpty(prefixes, spec.Name)
		matched := false
		for _, prefix := range prefixes {
			matched = matched || strings.HasPrefix(spec.Name, prefix)
		}
		s.True(matched, spec.Name)
		s.False(strings.HasPrefix(spec.Name, "derived."), spec.Name)
	}
}

func (s *RegistryTestSuite) TestSignalsAreSortedWithFamilyTemplates() {
	signals := s.signals(SignalScope{}).Signals()

	for i := 1; i < len(signals); i++ {
		s.Less(signals[i-1].Name, signals[i].Name)
	}
	families := 0
	for _, spec := range signals {
		if spec.Family {
			families++
		}
	}
	s.Equal(4, families)
	s.Len(signals, len(builtInSignals)+families)
}

func (s *RegistryTestSuite) TestFingerprint() {
	first := s.signals(customerScope()).Fingerprint()
	again := s.signals(customerScope()).Fingerprint()
	reordered := customerScope()
	reordered.UserTypes = append([]UserTypeSchema{{Name: "admin"}}, reordered.UserTypes...)
	changed := customerScope()
	changed.UserTypes[0].Attributes[2].Type = schemaTypeString

	s.Len(first, 64)
	s.Equal(first, again)
	s.Equal(first, s.signals(reordered).Fingerprint(), "a user type with no attributes adds no signal")
	s.NotEqual(first, s.signals(changed).Fingerprint())
	s.NotEqual(first, s.signals(SignalScope{}).Fingerprint())
}

func (s *RegistryTestSuite) TestRegistryCompilesRules() {
	e := Initialize()
	d, diagnostics := e.Parse([]byte(minimal(`{"op":"all","of":[` +
		`{"op":"eq","signal":"request.header.X-Network-Zone","value":"corporate","ci":true},` +
		`{"op":"gt","signal":"user.creditLimit","value":1000},` +
		`{"op":"gte","signal":"extension.age_service.age","value":18}]}`)))
	s.Require().Empty(diagnostics)

	p, diagnostics := e.Compile(d, s.signals(customerScope()))

	s.Empty(diagnostics)
	s.Require().NotNil(p)
	s.Equal([][]string{{"request.header.x-network-zone", "extension.age_service.age"}, {"user.creditLimit"}},
		p.Stages())
}

func (s *RegistryTestSuite) TestCostClassText() {
	text, err := CostStore.MarshalText()

	s.NoError(err)
	s.Equal("store", string(text))
	s.Equal("local", CostLocal.String())
	s.Equal("remote", CostRemote.String())
}
