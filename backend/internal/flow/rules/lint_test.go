// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type LintTestSuite struct {
	suite.Suite
}

func TestLintTestSuite(t *testing.T) {
	suite.Run(t, new(LintTestSuite))
}

// rulesOf returns a decision with one rule per condition, named r0, r1 and so on.
func rulesOf(conditions ...string) string {
	rules := make([]string, len(conditions))
	for i, when := range conditions {
		rules[i] = `{"id":"r` + strconv.Itoa(i) + `","when":` + when + `,"nextNode":"n"}`
	}
	return `{"rules":[` + strings.Join(rules, ",") + `],"default":{"nextNode":"d"},"unknown":{"nextNode":"u"}}`
}

// lint compiles a decision against the customer scope and returns the lint diagnostics alone.
func (s *LintTestSuite) lint(raw string) []Diagnostic {
	d, diagnostics := newParser(defaultLimits()).parse([]byte(raw))
	s.Require().Empty(diagnostics)
	c := newCompiler(newSignalRegistry(customerScope()))
	p, _ := c.compile(d)
	s.Require().NotNil(p)
	c.diagnostics = nil
	c.lint(d)
	return c.diagnostics
}

func (s *LintTestSuite) TestNeverTrue() {
	never := map[string]string{
		"ordering on a text signal":         `{"op":"gt","signal":"user.tier","value":"a"}`,
		"a literal a boolean cannot read":   `{"op":"eq","signal":"user.verified","value":"yes"}`,
		"a literal that cannot be ordered":  `{"op":"gt","signal":"extension.age_service.band","value":"abc"}`,
		"olderThan without a period":        `{"op":"olderThan","signal":"session.authTime","value":"soon"}`,
		"olderThan on a text signal":        `{"op":"olderThan","signal":"user.tier","value":"PT1H"}`,
		"a value outside the declared list": `{"op":"eq","signal":"user.verified","value":["yes","no"]}`,
		"a condition and its negation": `{"op":"all","of":[{"op":"exists","signal":"user.groups"},` +
			`{"op":"not","of":{"op":"exists","signal":"user.groups"}}]}`,
		"a group with a never-true child": `{"op":"all","of":[{"op":"exists","signal":"user.groups"},` +
			`{"op":"gt","signal":"user.tier","value":"a"}]}`,
	}
	for name, when := range never {
		s.Run(name, func() {
			s.Equal([]Diagnostic{newDiagnostic("rules[0].when", CodeNeverTrue, map[string]string{paramRuleID: "r0"})},
				s.lint(rulesOf(when)))
		})
	}
}

func (s *LintTestSuite) TestCanBeTrue() {
	possible := []string{
		`{"op":"exists","signal":"user.groups"}`,
		`{"op":"isEmpty","signal":"user.groups"}`,
		`{"op":"gt","signal":"extension.age_service.band","value":"5"}`,
		`{"op":"gt","signal":"user.creditLimit","ref":"extension.age_service.age"}`,
		`{"op":"olderThan","signal":"extension.age_service.band","value":"PT1H"}`,
		`{"op":"eq","signal":"user.verified","value":["yes",true]}`,
		`{"op":"any","of":[{"op":"gt","signal":"user.tier","value":"a"},{"op":"exists","signal":"user.groups"}]}`,
		`{"op":"all","of":[{"op":"exists","signal":"user.groups"},` +
			`{"op":"not","of":{"op":"exists","signal":"user.roles"}}]}`,
	}
	for _, when := range possible {
		s.Empty(s.lint(rulesOf(when)), when)
	}
}

func (s *LintTestSuite) TestShadowedRules() {
	groups := `{"op":"exists","signal":"user.groups"}`
	neverFalse := map[string]string{
		"the negation of a never-true condition": `{"op":"not","of":{"op":"gt","signal":"user.tier","value":"a"}}`,
		"a condition or its negation":            `{"op":"any","of":[` + groups + `,{"op":"not","of":` + groups + `}]}`,
	}
	for name, first := range neverFalse {
		s.Run(name, func() {
			s.Equal([]Diagnostic{
				newDiagnostic("rules[1]", CodeShadowedRule, map[string]string{paramRuleID: "r0"}),
				newDiagnostic("rules[2]", CodeShadowedRule, map[string]string{paramRuleID: "r0"}),
			}, s.lint(rulesOf(first, groups, `{"op":"exists","signal":"user.roles"}`)))
		})
	}
	s.Run("the same condition again", func() {
		repeated := `{"op":"all","of":[` + groups + `,{"op":"gt","signal":"user.creditLimit","value":5}]}`

		s.Equal([]Diagnostic{newDiagnostic("rules[2]", CodeShadowedRule, map[string]string{paramRuleID: "r0"})},
			s.lint(rulesOf(repeated, `{"op":"exists","signal":"user.roles"}`, repeated)))
	})
}

func (s *LintTestSuite) TestSubjectTrust() {
	cases := map[string]bool{
		`{"op":"eq","signal":"input.username","value":"admin"}`: true,
		`{"op":"all","of":[{"op":"eq","signal":"request.header.X-Zone","value":"corp"},` +
			`{"op":"eq","signal":"input.username","ref":"request.query.user"}]}`: true,
		`{"op":"all","of":[{"op":"eq","signal":"input.username","value":"admin"},` +
			`{"op":"exists","signal":"user.groups"}]}`: false,
		`{"op":"eq","signal":"user.email","ref":"input.email"}`: false,
	}
	for when, warned := range cases {
		var expected []Diagnostic
		if warned {
			expected = []Diagnostic{newDiagnostic("rules[0].when", CodeSubjectTrust, nil)}
		}
		s.Equal(expected, s.lint(rulesOf(when)), when)
	}
}

func (s *LintTestSuite) TestTruthSets() {
	s.Equal(setFalse|setUnknown, mapSet(setFalse|setUnknown, andTruth, setAny))
	s.Equal(setAny, mapSet(setFalse|setTrue, orTruth, setUnknown|setFalse))
	s.Equal(setTrue, mapSet(setFalse, func(a, _ Truth) Truth { return notTruth(a) }, setAny))
}
