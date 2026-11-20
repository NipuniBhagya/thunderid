// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

// specExample is the decision node of the specification: approvers need MFA off the corporate
// network, under-age users are denied, and missing data denies.
const specExample = `{"grammarVersion":1,"rules":[
 {"id":"privileged","label":"Payment approvers need MFA","when":{"op":"all","of":[
   {"op":"eq","signal":"user.groups","value":["payments-approver","treasury"]},
   {"op":"not","of":{"op":"eq","signal":"request.header.X-Network-Zone","value":"corporate","ci":true}}]},
  "nextNode":"mfa_prompt"},
 {"id":"under_age","label":"Under 18","when":{"op":"not","of":
   {"op":"gte","signal":"extension.age_service.age","value":18}},"nextNode":"deny_access"}],
 "default":{"label":"Continue","nextNode":"issue_token"},
 "unknown":{"label":"Cannot decide","nextNode":"deny_access"},
 "tests":[
  {"name":"approver off the corporate network needs MFA","facts":{"user.groups":["payments-approver"],
    "request.header.X-Network-Zone":"public","extension.age_service.age":30},"expect":"mfa_prompt"},
  {"name":"directory unavailable","unresolved":["user.groups"],"expect":"deny_access"}]}`

// exampleFlow is the flow around the decision: a login, then an extension step that asks a service
// for the user's age, then the decision.
func exampleFlow() FlowGraph {
	return FlowGraph{Start: "start", Nodes: []GraphNode{
		{ID: "start", Edges: []GraphEdge{edge("login")}},
		{ID: "login", Edges: []GraphEdge{edge("age_service", SignalUserID, SignalUserAuthenticated)}},
		{ID: "age_service", Edges: []GraphEdge{edge("access_check", "extension.age_service.age")}},
		{ID: "access_check", Edges: []GraphEdge{edge("mfa_prompt"), edge("deny_access"), edge("issue_token")}},
		{ID: "mfa_prompt", End: true}, {ID: "deny_access", End: true}, {ID: "issue_token", End: true},
	}}
}

type ValidatorTestSuite struct {
	suite.Suite
	engine EngineInterface
}

func TestValidatorTestSuite(t *testing.T) {
	suite.Run(t, new(ValidatorTestSuite))
}

func (s *ValidatorTestSuite) SetupTest() {
	s.engine = Initialize()
}

// context returns the validation context of the access_check node in a flow graph.
func (s *ValidatorTestSuite) context(graph FlowGraph) ValidationContext {
	signals, diagnostics := s.engine.Signals(customerScope())
	s.Require().Empty(diagnostics)
	var ids []string
	for _, n := range graph.Nodes {
		ids = append(ids, n.ID)
	}
	return ValidationContext{
		NodeID: "access_check", NodeIDs: ids, Signals: signals, Availability: s.engine.Availability(graph),
		Now: testNow,
	}
}

// validate validates a decision as the access_check node of the example flow.
func (s *ValidatorTestSuite) validate(raw string) (PlanInterface, []Diagnostic) {
	_, p, diagnostics := s.engine.Validate([]byte(raw), s.context(exampleFlow()))
	return p, diagnostics
}

// diagnostic is a diagnostic of the access_check node.
func diagnostic(path string, code DiagnosticCode, params map[string]string) Diagnostic {
	d := newDiagnostic(path, code, params)
	d.NodeID = "access_check"
	return d
}

// decisionWith returns a one-rule decision with the condition, arms to the example flow's nodes, and the
// tests given as JSON.
func decisionWith(when, tests string) string {
	return `{"rules":[{"id":"r","when":` + when + `,"nextNode":"mfa_prompt"}],` +
		`"default":{"nextNode":"issue_token"},"unknown":{"nextNode":"deny_access"},"tests":[` + tests + `]}`
}

func (s *ValidatorTestSuite) TestTheSpecificationExampleIsValid() {
	p, diagnostics := s.validate(specExample)

	s.Empty(diagnostics)
	s.Require().NotNil(p)
	s.Equal([][]string{{"request.header.x-network-zone", "extension.age_service.age"}, {"user.groups"}}, p.Stages())
}

func (s *ValidatorTestSuite) TestStructuralErrorsAreReportedFirst() {
	p, diagnostics := s.validate(`{"rules":[{"id":"r","when":{"op":"eq","signal":"user.group","value":"x"},` +
		`"nextNode":"nowhere","colour":"red"}],"default":{"nextNode":"issue_token"},` +
		`"unknown":{"nextNode":"deny_access"}}`)

	s.Nil(p)
	s.Equal([]Diagnostic{diagnostic("rules[0].colour", CodeUnknownField, map[string]string{paramField: "colour"})},
		diagnostics)
}

func (s *ValidatorTestSuite) TestNextNodesMustExist() {
	p, diagnostics := s.validate(`{"rules":[{"id":"r","when":{"op":"exists","signal":"user.id"},` +
		`"nextNode":"nowhere"}],"default":{"nextNode":"gone"},"unknown":{"nextNode":"deny_access"}}`)

	s.Nil(p)
	s.Equal([]Diagnostic{
		diagnostic("rules[0].nextNode", CodeUnknownNode, map[string]string{paramValue: "nowhere"}),
		diagnostic("default.nextNode", CodeUnknownNode, map[string]string{paramValue: "gone"}),
	}, diagnostics)
}

func (s *ValidatorTestSuite) TestEveryProblemIsCollected() {
	p, diagnostics := s.validate(decisionWith(`{"op":"all","of":[`+
		`{"op":"eq","signal":"user.group","value":"x"},`+
		`{"op":"startsWith","signal":"user.creditLimit","value":"1"},`+
		`{"op":"exists","signal":"input.username"}]}`, ""))

	s.Nil(p)
	s.Equal([]DiagnosticCode{CodeUnknownSignal, CodeOperatorComparator, CodeSignalUnavailable}, codes(diagnostics))
	for _, d := range diagnostics {
		s.Equal("access_check", d.NodeID)
	}
}

func (s *ValidatorTestSuite) TestAnExtensionFieldWithoutAValidNameIsExplained() {
	ctx := s.context(exampleFlow())
	signals, _ := s.engine.Signals(SignalScope{ExtensionSteps: []ExtensionStep{
		{NodeID: "age-service", ResponseKeys: []string{"age"}},
	}})
	ctx.Signals = signals

	_, p, diagnostics := s.engine.Validate([]byte(decisionWith(
		`{"op":"gte","signal":"extension.age-service.age","value":18}`, "")), ctx)

	s.Nil(p)
	s.Equal([]Diagnostic{diagnostic("rules[0].when.signal", CodeOutputName,
		map[string]string{paramName: "extension.age-service.age"})}, diagnostics)
}

func (s *ValidatorTestSuite) TestAvailability() {
	branching := exampleFlow()
	branching.Nodes[0].Edges = append(branching.Nodes[0].Edges, edge("access_check", "input.username"))

	_, p, diagnostics := s.engine.Validate([]byte(decisionWith(`{"op":"any","of":[`+
		`{"op":"eq","signal":"input.username","value":"x"},`+
		`{"op":"eq","signal":"flow.type","ref":"input.age"}]}`, "")), s.context(branching))

	s.Nil(p)
	s.Equal([]Diagnostic{
		diagnostic("rules[0].when.of[0].signal", CodeSignalSometimesAbsent,
			map[string]string{paramName: "input.username"}),
		diagnostic("rules[0].when.of[1].ref", CodeSignalUnavailable, map[string]string{paramName: "input.age"}),
	}, diagnostics)
}

func (s *ValidatorTestSuite) TestDirectoryDataBeforeAuthentication() {
	identifyOnly := exampleFlow()
	identifyOnly.Nodes[1].Edges[0].Produces = []string{SignalUserID}
	sometimes := exampleFlow()
	sometimes.Nodes[0].Edges = append(sometimes.Nodes[0].Edges, edge("age_service", SignalUserID))
	when := `{"op":"all","of":[{"op":"eq","signal":"user.groups","value":"admins"},` +
		`{"op":"exists","signal":"user.id"},{"op":"gt","signal":"user.creditLimit","value":5}]}`
	warnings := []Diagnostic{
		diagnostic("rules[0].when.of[0].signal", CodeUnauthenticatedUser, map[string]string{paramName: "user.groups"}),
		diagnostic("rules[0].when.of[2].signal", CodeUnauthenticatedUser,
			map[string]string{paramName: "user.creditLimit"}),
	}

	for name, graph := range map[string]FlowGraph{"identified only": identifyOnly, "not on every path": sometimes} {
		s.Run(name, func() {
			_, p, diagnostics := s.engine.Validate([]byte(decisionWith(when, "")), s.context(graph))

			s.NotNil(p, "a warning does not refuse the save")
			s.Equal(warnings, diagnostics)
		})
	}
	_, _, diagnostics := s.engine.Validate([]byte(decisionWith(when, "")), s.context(exampleFlow()))
	s.Empty(diagnostics)
}

func (s *ValidatorTestSuite) TestAvailabilityIsSkippedWhereThereAreNoPaths() {
	unreachable := exampleFlow()
	unreachable.Nodes[2].Edges = nil
	withoutGraph := s.context(exampleFlow())
	withoutGraph.Availability = nil
	when := decisionWith(`{"op":"exists","signal":"input.username"}`, "")

	_, _, unreachableDiagnostics := s.engine.Validate([]byte(when), s.context(unreachable))
	_, _, ungraphedDiagnostics := s.engine.Validate([]byte(when), withoutGraph)

	s.Equal([]DiagnosticCode{CodeSubjectTrust}, codes(unreachableDiagnostics))
	s.Equal([]DiagnosticCode{CodeSubjectTrust}, codes(ungraphedDiagnostics))
}

func (s *ValidatorTestSuite) TestNodeTests() {
	ctx := s.context(exampleFlow())
	ctx.Availability = nil
	cases := []struct {
		name     string
		when     string
		tests    string
		expected []Diagnostic
	}{
		{"a failing test", `{"op":"eq","signal":"user.groups","value":"admins"}`,
			`{"name":"admins get MFA","facts":{"user.groups":"staff"},"expect":"mfa_prompt"}`,
			[]Diagnostic{diagnostic("tests[0]", CodeTestFailed, map[string]string{
				paramName: "admins get MFA", paramExpected: "mfa_prompt", paramActual: "issue_token"})}},
		{"signals a test does not supply are absent", `{"op":"exists","signal":"user.groups"}`,
			`{"name":"nothing","expect":"issue_token"}`, nil},
		{"unresolved signals are unknown", `{"op":"exists","signal":"user.groups"}`,
			`{"name":"directory down","unresolved":["user.groups"],"expect":"deny_access"}`, nil},
		{"facts name signals in any spelling", `{"op":"eq","signal":"request.header.x-zone","value":"corp"}`,
			`{"name":"header","facts":{"request.header.X-Zone":"corp"},"expect":"mfa_prompt"}`,
			[]Diagnostic{diagnostic("rules[0].when", CodeSubjectTrust, nil)}},
		{"the context sets the flow type and the application",
			`{"op":"all","of":[{"op":"eq","signal":"flow.type","value":"REGISTRATION"},` +
				`{"op":"eq","signal":"application.id","value":"app-1"}]}`,
			`{"name":"context","context":{"flowType":"REGISTRATION","applicationId":"app-1"},` +
				`"expect":"mfa_prompt"}`, nil},
		{"tests evaluate at the validation time", `{"op":"olderThan","signal":"session.authTime","value":"PT1H"}`,
			`{"name":"stale","facts":{"session.authTime":"2026-11-18T10:00:00Z"},"expect":"mfa_prompt"}`, nil},
		{"unknown signals in a test", `{"op":"exists","signal":"user.groups"}`,
			`{"name":"typo","facts":{"user.group":"x"},"unresolved":["user.grups"],"expect":"mfa_prompt"}`,
			[]Diagnostic{
				diagnostic("tests[0].facts.user.group", CodeUnknownSignal, map[string]string{paramName: "user.group"}),
				diagnostic("tests[0].unresolved[0]", CodeUnknownSignal, map[string]string{paramName: "user.grups"}),
			}},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			_, p, diagnostics := s.engine.Validate([]byte(decisionWith(tc.when, tc.tests)), ctx)

			s.Equal(tc.expected, diagnostics)
			s.Equal(!hasErrors(tc.expected), p != nil, "a failing test refuses the plan")
		})
	}
}

func (s *ValidatorTestSuite) TestTheTestLimit() {
	tests := strings.Repeat(`{"name":"t","expect":"issue_token"},`, defaultMaxTests+1)

	p, diagnostics := s.validate(decisionWith(`{"op":"exists","signal":"user.id"}`, strings.TrimSuffix(tests, ",")))

	s.Nil(p)
	s.Equal([]DiagnosticCode{CodeLimit}, codes(diagnostics))
}

func (s *ValidatorTestSuite) TestTheReturnedPlanEvaluates() {
	p, _ := s.validate(specExample)
	f := p.AcquireFrame(testNow)
	defer f.Release()
	f.SetValues("request.header.x-network-zone", []string{"public"})
	f.SetValues("extension.age_service.age", []string{"16"})
	f.SetValues("user.groups", []string{"staff"})

	s.Equal(Outcome{SelectedBy: SelectedByRule, RuleID: "under_age", NextNode: "deny_access", Settled: true},
		f.Evaluate())
}
