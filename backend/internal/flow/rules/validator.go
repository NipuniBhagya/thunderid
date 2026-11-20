// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"maps"
	"slices"
	"time"
)

// ValidationContext is what the rule validator knows about the flow a decision node is in.
type ValidationContext struct {
	// NodeID is the decision node. Every diagnostic carries it.
	NodeID string
	// NodeIDs are the nodes of the flow, which every rule and arm must lead to.
	NodeIDs []string
	// Signals are the signals of the node's scope.
	Signals SignalRegistryInterface
	// Availability says which signals exist at the node. Without it, availability is not checked.
	Availability AvailabilityInterface
	// Now is the time node tests evaluate at.
	Now time.Time
}

// validator checks one decision node and runs its tests.
type validator struct {
	limits      limits
	context     ValidationContext
	diagnostics []Diagnostic
}

// Validate checks a decision node's rules in the context of its flow, compiles them and runs the node's
// tests, and reports every problem it finds. It returns the plan only when there is no error. Problems
// that need a well-formed decision, such as unknown signals, are reported once its structure is valid.
func (e *ruleEngine) Validate(raw []byte, vc ValidationContext) (*Decision, PlanInterface, []Diagnostic) {
	v := &validator{limits: e.limits, context: vc}
	d, p := v.validate(raw)
	for i := range v.diagnostics {
		v.diagnostics[i].NodeID = vc.NodeID
	}
	if p == nil || hasErrors(v.diagnostics) {
		return d, nil, v.diagnostics
	}
	return d, p, v.diagnostics
}

// validate runs every check in order: structure, next nodes, signals and comparators, availability,
// lints, compilation and tests.
func (v *validator) validate(raw []byte) (*Decision, *plan) {
	d, diagnostics := newParser(v.limits).parse(raw)
	v.diagnostics = diagnostics
	if d == nil || hasErrors(diagnostics) {
		return d, nil
	}
	v.checkNextNodes(d)
	c := newCompiler(v.context.Signals)
	p, compiled := c.compile(d)
	v.diagnostics = append(v.diagnostics, v.explainUnknownSignals(compiled)...)
	v.checkAvailability(d)
	if p == nil {
		return d, nil
	}
	c.diagnostics = nil
	c.lint(d)
	v.diagnostics = append(v.diagnostics, c.diagnostics...)
	v.runTests(d, p)
	return d, p
}

// checkNextNodes reports a rule or arm that leads to a node the flow does not have.
func (v *validator) checkNextNodes(d *Decision) {
	check := func(path, nextNode string) {
		if !slices.Contains(v.context.NodeIDs, nextNode) {
			v.add(join(path, fieldNextNode), CodeUnknownNode, map[string]string{paramValue: nextNode})
		}
	}
	for i := range d.Rules {
		check(index(fieldRules, i), d.Rules[i].NextNode)
	}
	check(fieldDefault, d.Default.NextNode)
	check(fieldUnknown, d.Unknown.NextNode)
}

// explainUnknownSignals turns an unknown signal that is an extension step's field without a valid
// signal name into the reason it is not a signal.
func (v *validator) explainUnknownSignals(diagnostics []Diagnostic) []Diagnostic {
	for i, d := range diagnostics {
		if d.Code != CodeUnknownSignal {
			continue
		}
		if code, rejected := v.context.Signals.rejection(d.Params[paramName]); rejected {
			diagnostics[i] = newDiagnostic(d.Path, code, d.Params)
		}
	}
	return diagnostics
}

// checkAvailability reports, for every signal a rule reads, whether it can exist at the node, and warns
// when a rule reads the identified account's directory data where the user may not have authenticated.
// A node no path reaches has no paths to check; the flow validator reports it as unreachable.
func (v *validator) checkAvailability(d *Decision) {
	a := v.context.Availability
	if a == nil || !a.Reachable(v.context.NodeID) {
		return
	}
	authenticated := PresenceNever
	if spec, ok := v.context.Signals.Lookup(SignalUserAuthenticated); ok {
		authenticated = a.Presence(v.context.NodeID, spec)
	}
	for i := range d.Rules {
		walkLeaves(d.Rules[i].When, join(index(fieldRules, i), fieldWhen), func(p *Predicate, path string) {
			v.checkSignal(path, fieldSignal, p.Signal, authenticated)
			v.checkSignal(path, fieldRef, p.Ref, authenticated)
		})
	}
}

// checkSignal reports whether one signal a leaf reads exists at the node.
func (v *validator) checkSignal(leafPath, field, name string, authenticated Presence) {
	spec, ok := v.context.Signals.Lookup(name)
	if !ok {
		return
	}
	path := join(leafPath, field)
	params := map[string]string{paramName: spec.Name}
	switch v.context.Availability.Presence(v.context.NodeID, spec) {
	case PresenceNever:
		v.add(path, CodeSignalUnavailable, params)
		return
	case PresenceSometimes:
		v.add(path, CodeSignalSometimesAbsent, params)
	}
	if spec.AccountData && authenticated != PresenceAlways {
		v.add(path, CodeUnauthenticatedUser, params)
	}
}

// walkLeaves calls visit for every leaf of a condition with its path.
func walkLeaves(p *Predicate, path string, visit func(p *Predicate, path string)) {
	switch {
	case p == nil:
	case p.Op == opNot:
		for _, child := range p.Of {
			walkLeaves(child, join(path, fieldOf), visit)
		}
	case p.isGroup():
		for i, child := range p.Of {
			walkLeaves(child, index(join(path, fieldOf), i), visit)
		}
	default:
		visit(p, path)
	}
}

// runTests evaluates each node test against the plan, using only the values the test supplies: the
// facts have their values, the unresolved signals behave as if their source failed, and every other
// signal is absent. A test that names a signal that does not exist is reported and not run.
func (v *validator) runTests(d *Decision, p *plan) {
	for i := range d.Tests {
		test := &d.Tests[i]
		path := index(fieldTests, i)
		f, _ := p.AcquireFrame(v.context.Now).(*frame)
		if v.supply(f, test, path) {
			if outcome := f.Evaluate(); outcome.NextNode != test.Expect {
				v.add(path, CodeTestFailed, map[string]string{
					paramName: test.Name, paramExpected: test.Expect, paramActual: outcome.NextNode,
				})
			}
		}
		f.Release()
	}
}

// supply sets the values of a test in the frame and reports whether every signal it names exists.
func (v *validator) supply(f *frame, test *DecisionTest, path string) bool {
	ok := true
	lookup := func(path, name string) (SignalSpec, bool) {
		spec, found := v.context.Signals.Lookup(name)
		if !found {
			v.add(path, CodeUnknownSignal, map[string]string{paramName: name})
			ok = false
		}
		return spec, found
	}
	if test.Context != nil {
		for name, value := range map[string]string{
			signalFlowType: test.Context.FlowType, signalApplicationID: test.Context.ApplicationID,
		} {
			if value != "" {
				f.SetValues(name, []string{value})
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(test.Facts)) {
		if spec, found := lookup(join(join(path, fieldFacts), name), name); found {
			fact := test.Facts[name]
			f.SetValues(spec.Name, fact.Atoms())
		}
	}
	for j, name := range test.Unresolved {
		if spec, found := lookup(index(join(path, fieldUnresolved), j), name); found {
			f.SetUnresolved(spec.Name)
		}
	}
	for i := range f.slots {
		if f.slots[i].state == slotUnfetched {
			f.slots[i].state = slotAbsent
		}
	}
	return ok
}

// add records a diagnostic.
func (v *validator) add(path string, code DiagnosticCode, params map[string]string) {
	v.diagnostics = append(v.diagnostics, newDiagnostic(path, code, params))
}
