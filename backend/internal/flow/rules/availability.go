// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"maps"
	"math/bits"
	"slices"
)

// FlowGraph is the shape of a flow that the signal availability analysis reads: which node follows
// which, and which signals exist once a step has been taken. The flow validator builds it from the flow
// definition: executor outputs on the matching exits, prompt inputs on their actions, extension outputs
// on an extension step's success exit, and a called flow's summary on a call node's exit.
type FlowGraph struct {
	Start string
	Nodes []GraphNode
}

// GraphNode is a node of the flow graph. End marks a node where the flow finishes.
type GraphNode struct {
	ID    string
	Edges []GraphEdge
	End   bool
}

// GraphEdge is a way out of a node, and the signals that exist once the flow has taken it.
type GraphEdge struct {
	To       string
	Produces []string
}

// Presence says whether a signal exists when the flow reaches a node.
type Presence string

// Presences of a signal at a node.
const (
	// PresenceAlways is a signal that exists on every path into the node.
	PresenceAlways Presence = "ALWAYS"
	// PresenceSometimes is a signal that exists on some paths into the node only.
	PresenceSometimes Presence = "SOMETIMES"
	// PresenceNever is a signal that exists on no path into the node, or a node no path reaches.
	PresenceNever Presence = "NEVER"
)

// AvailabilityInterface answers, for each node of a flow, which signals exist when the flow gets there.
type AvailabilityInterface interface {
	// Reachable reports whether any path from the start reaches the node.
	Reachable(nodeID string) bool
	// Presence says whether the signal exists at the node. A signal that always exists is present
	// everywhere; a signal that exists with another, such as the user's groups with the user, is present
	// where that one is.
	Presence(nodeID string, spec SignalSpec) Presence
	// SignalsAtEveryEnd lists the produced signals that exist at every end of the flow, which is what a
	// flow that calls this one can rely on.
	SignalsAtEveryEnd() []string
}

// bitset is a set of produced signals, one bit each.
type bitset []uint64

// availability implements AvailabilityInterface with two sets per reachable node: must, the signals
// produced on every path into it, and may, those produced on some path.
type availability struct {
	signals map[string]int
	must    map[string]bitset
	may     map[string]bitset
	ends    []string
}

// incoming is an edge into a node: where it comes from and what taking it produces.
type incoming struct {
	from     string
	produces bitset
}

// analyseAvailability runs a forward dataflow over the graph until neither set of any node changes.
// The cost is the number of edges times the number of produced signals over 64, per round.
func analyseAvailability(g FlowGraph) *availability {
	a := &availability{signals: map[string]int{}, must: map[string]bitset{}, may: map[string]bitset{}}
	for _, node := range g.Nodes {
		for _, edge := range node.Edges {
			for _, signal := range edge.Produces {
				if _, ok := a.signals[signal]; !ok {
					a.signals[signal] = len(a.signals)
				}
			}
		}
	}
	reachable, edgesInto := a.reach(g)
	words := (len(a.signals) + bits.UintSize - 1) / bits.UintSize
	for _, id := range reachable {
		a.must[id], a.may[id] = full(words), make(bitset, words)
	}
	if len(reachable) == 0 {
		return a
	}
	a.must[g.Start] = make(bitset, words)
	for changed := true; changed; {
		changed = false
		for _, id := range reachable {
			changed = a.transfer(id, id == g.Start, edgesInto[id]) || changed
		}
	}
	for _, node := range g.Nodes {
		if _, ok := a.must[node.ID]; ok && node.End {
			a.ends = append(a.ends, node.ID)
		}
	}
	return a
}

// reach finds the nodes reachable from the start, in the order they are found, and the edges into each.
// Edges to nodes that do not exist are ignored; the flow validator reports them.
func (a *availability) reach(g FlowGraph) ([]string, map[string][]incoming) {
	nodes := make(map[string]*GraphNode, len(g.Nodes))
	for i := range g.Nodes {
		nodes[g.Nodes[i].ID] = &g.Nodes[i]
	}
	edgesInto := map[string][]incoming{}
	if nodes[g.Start] == nil {
		return nil, edgesInto
	}
	reachable := []string{g.Start}
	seen := map[string]bool{g.Start: true}
	for i := 0; i < len(reachable); i++ {
		for _, edge := range nodes[reachable[i]].Edges {
			if nodes[edge.To] == nil {
				continue
			}
			into := incoming{from: reachable[i], produces: a.set(edge.Produces)}
			edgesInto[edge.To] = append(edgesInto[edge.To], into)
			if !seen[edge.To] {
				seen[edge.To] = true
				reachable = append(reachable, edge.To)
			}
		}
	}
	return reachable, edgesInto
}

// transfer recomputes a node's sets from its incoming edges and reports whether they changed. Nothing is
// produced before the start, so the start's must set stays empty.
func (a *availability) transfer(id string, start bool, edges []incoming) bool {
	must, may := a.must[id], a.may[id]
	changed := false
	for w := range may {
		m, y := ^uint64(0), may[w]
		if start {
			m = 0
		}
		for _, e := range edges {
			m &= a.must[e.from][w] | e.produces[w]
			y |= a.may[e.from][w] | e.produces[w]
		}
		if m != must[w] || y != may[w] {
			must[w], may[w], changed = m, y, true
		}
	}
	return changed
}

// set returns the bitset of the named signals.
func (a *availability) set(signals []string) bitset {
	s := make(bitset, (len(a.signals)+bits.UintSize-1)/bits.UintSize)
	for _, signal := range signals {
		i := a.signals[signal]
		s[i/bits.UintSize] |= 1 << (i % bits.UintSize)
	}
	return s
}

// full returns a bitset with every bit set.
func full(words int) bitset {
	s := make(bitset, words)
	for i := range s {
		s[i] = ^uint64(0)
	}
	return s
}

// has reports whether the set holds the signal with index i.
func (s bitset) has(i int) bool {
	return s[i/bits.UintSize]&(1<<(i%bits.UintSize)) != 0
}

// Reachable reports whether any path from the start reaches the node.
func (a *availability) Reachable(nodeID string) bool {
	_, ok := a.must[nodeID]
	return ok
}

// Presence says whether the signal exists at the node.
func (a *availability) Presence(nodeID string, spec SignalSpec) Presence {
	if !a.Reachable(nodeID) {
		return PresenceNever
	}
	if spec.ProducedBy == ProducerAlways {
		return PresenceAlways
	}
	i, produced := a.signals[cmp.Or(spec.With, spec.Name)]
	switch {
	case !produced:
		return PresenceNever
	case a.must[nodeID].has(i):
		return PresenceAlways
	case a.may[nodeID].has(i):
		return PresenceSometimes
	}
	return PresenceNever
}

// SignalsAtEveryEnd lists, sorted, the produced signals that exist at every reachable end of the flow.
// A flow that never ends produces nothing for its callers.
func (a *availability) SignalsAtEveryEnd() []string {
	if len(a.ends) == 0 {
		return nil
	}
	var signals []string
	for _, signal := range slices.Sorted(maps.Keys(a.signals)) {
		i := a.signals[signal]
		if !slices.ContainsFunc(a.ends, func(end string) bool { return !a.must[end].has(i) }) {
			signals = append(signals, signal)
		}
	}
	return signals
}
