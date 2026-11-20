// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
)

// truthSet is a set of the truth values a condition can take, one bit each.
type truthSet uint8

// Truth sets.
const (
	setFalse   truthSet = 1 << TruthFalse
	setUnknown truthSet = 1 << TruthUnknown
	setTrue    truthSet = 1 << TruthTrue
	setAny              = setFalse | setUnknown | setTrue
)

// lint reports rules that can never decide: a rule whose condition can never be true, and a rule that
// an earlier rule always pre-empts, either because the earlier condition can never be false or because
// it is the same condition. It also reports rules that read only values the user or the client
// supplied. These are best-effort checks, not proofs: a rule they pass can still be wrong.
func (c *compiler) lint(d *Decision) {
	alwaysDecides := ""
	seen := map[string]string{}
	for i, t := range c.trees {
		path := index(fieldRules, i)
		id := d.Rules[i].ID
		possible := c.possible(t)
		if possible&setTrue == 0 {
			c.add(join(path, fieldWhen), CodeNeverTrue, map[string]string{paramRuleID: id})
		}
		canonical := canonicalKey(t)
		earlier, repeated := seen[canonical]
		switch {
		case alwaysDecides != "":
			c.add(path, CodeShadowedRule, map[string]string{paramRuleID: alwaysDecides})
		case repeated:
			c.add(path, CodeShadowedRule, map[string]string{paramRuleID: earlier})
		}
		if possible&setFalse == 0 && alwaysDecides == "" {
			alwaysDecides = id
		}
		if !repeated {
			seen[canonical] = id
		}
		c.lintTrust(t, join(path, fieldWhen))
	}
}

// lintTrust reports a condition that reads only signals with trust subject, whose every value the user
// or the client controls.
func (c *compiler) lintTrust(t *tree, path string) {
	subjectOnly, readsAny := true, false
	var walk func(*tree)
	walk = func(n *tree) {
		for _, child := range n.children {
			walk(child)
		}
		if len(n.children) > 0 {
			return
		}
		for _, name := range []string{n.pred.Signal, n.pred.Ref} {
			if spec, ok := c.catalog.Lookup(name); ok {
				readsAny = true
				subjectOnly = subjectOnly && spec.Trust == TrustSubject
			}
		}
	}
	walk(t)
	if readsAny && subjectOnly {
		c.add(path, CodeSubjectTrust, nil)
	}
}

// possible returns the truth values a normalised condition can take. Children are treated as
// independent, which can only add values, so a value missing from the result is one the condition can
// never take. A condition and its negation in the same group are the one dependency it tracks: p AND
// NOT p is never true, and p OR NOT p is never false.
func (c *compiler) possible(t *tree) truthSet {
	switch {
	case t.pred.Op == opNot:
		return mapSet(c.possible(t.children[0]), func(a, _ Truth) Truth { return notTruth(a) }, setAny)
	case t.pred.isGroup():
		combine, result, removed := andTruth, setTrue, setTrue
		if t.pred.Op == opAny {
			combine, result, removed = orTruth, setFalse, setFalse
		}
		for _, child := range t.children {
			result = mapSet(result, combine, c.possible(child))
		}
		if hasComplement(t.children) {
			result &^= removed
		}
		return result
	}
	if l := c.lowered[t.path]; l != nil && l.neverComparable() {
		return setFalse | setUnknown
	}
	return setAny
}

// mapSet applies a binary truth function to every pair of values from two sets.
func mapSet(a truthSet, f func(x, y Truth) Truth, b truthSet) truthSet {
	var result truthSet
	for x := TruthFalse; x <= TruthTrue; x++ {
		for y := TruthFalse; y <= TruthTrue; y++ {
			if a&(1<<x) != 0 && b&(1<<y) != 0 {
				result |= 1 << f(x, y)
			}
		}
	}
	return result
}

// hasComplement reports whether a group holds a condition and its negation.
func hasComplement(children []*tree) bool {
	plain := map[string]bool{}
	for _, child := range children {
		if child.pred.Op != opNot {
			plain[canonicalKey(child)] = true
		}
	}
	for _, child := range children {
		if child.pred.Op == opNot && plain[canonicalKey(child.children[0])] {
			return true
		}
	}
	return false
}

// canonicalKey returns the canonical JSON form of a condition, so that equal conditions compare equal
// however they were written.
func canonicalKey(t *tree) string {
	encoded, _ := json.Marshal(t.pred)
	return string(encoded)
}

// neverComparable reports whether a leaf can never be true: the operator needs what the declared
// comparator cannot do, olderThan has no usable period, or no value of the literal can ever be compared
// with a value of the signal.
func (l *leaf) neverComparable() bool {
	switch l.op {
	case opExists, opIsEmpty:
		return false
	case opOlderThan:
		return !l.periodOK || (l.cmp.pinned != cmpNone && l.cmp.pinned != cmpInstant)
	}
	if l.cmp.pinned != cmpNone && !l.cmp.pinned.offers(l.cmp.need) {
		return true
	}
	if l.refSlot >= 0 {
		return false
	}
	for i := range l.right {
		if (l.cmp.pinned == cmpNone && l.right[i].classes&l.cmp.allowed != 0) ||
			(l.cmp.pinned != cmpNone && l.cmp.recognises(&l.right[i])) {
			return false
		}
	}
	return true
}
