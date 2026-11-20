// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
)

type AvailabilityTestSuite struct {
	suite.Suite
}

func TestAvailabilityTestSuite(t *testing.T) {
	suite.Run(t, new(AvailabilityTestSuite))
}

// produced is a signal some step produces.
func produced(name string) SignalSpec {
	return SignalSpec{Name: name, ProducedBy: ProducerExecutor}
}

// edge returns an edge to a node that produces the signals.
func edge(to string, signals ...string) GraphEdge {
	return GraphEdge{To: to, Produces: signals}
}

// loginGraph is START → identify → login → decision, with a prompt branch that skips the login.
//
//	start ─▶ identify ─(user.id)─▶ choose ─password─▶ login ─(user.id, user.authenticated)─▶ decision
//	                                     └─magic─▶ decision (input.code)
func loginGraph() FlowGraph {
	return FlowGraph{Start: "start", Nodes: []GraphNode{
		{ID: "start", Edges: []GraphEdge{edge("identify")}},
		{ID: "identify", Edges: []GraphEdge{edge("choose", SignalUserID), edge("end")}},
		{ID: "choose", Edges: []GraphEdge{edge("login"), edge("decision", "input.code")}},
		{ID: "login", Edges: []GraphEdge{edge("decision", SignalUserID, SignalUserAuthenticated)}},
		{ID: "decision", Edges: []GraphEdge{edge("end")}},
		{ID: "end", End: true},
		{ID: "orphan", Edges: []GraphEdge{edge("end", "input.orphan")}},
	}}
}

func (s *AvailabilityTestSuite) TestPresence() {
	a := Initialize().Availability(loginGraph())

	s.Equal(PresenceAlways, a.Presence("decision", produced(SignalUserID)))
	s.Equal(PresenceSometimes, a.Presence("decision", produced(SignalUserAuthenticated)))
	s.Equal(PresenceSometimes, a.Presence("decision", produced("input.code")))
	s.Equal(PresenceNever, a.Presence("decision", produced("input.orphan")))
	s.Equal(PresenceNever, a.Presence("decision", produced("session.authTime")))
	s.Equal(PresenceNever, a.Presence("identify", produced(SignalUserID)), "a step's outputs exist after it")
}

func (s *AvailabilityTestSuite) TestSignalsThatAlwaysExistOrFollowAnother() {
	a := Initialize().Availability(loginGraph())

	s.Equal(PresenceAlways, a.Presence("start", SignalSpec{Name: "flow.type", ProducedBy: ProducerAlways}))
	s.Equal(PresenceAlways, a.Presence("decision",
		SignalSpec{Name: "user.groups", ProducedBy: ProducerExecutor, With: SignalUserID}))
	s.Equal(PresenceNever, a.Presence("choose",
		SignalSpec{Name: "user.groups", ProducedBy: ProducerExecutor, With: SignalUserAuthenticated}))
}

func (s *AvailabilityTestSuite) TestUnreachableNodes() {
	a := Initialize().Availability(loginGraph())

	s.True(a.Reachable("decision"))
	s.False(a.Reachable("orphan"))
	s.False(a.Reachable("missing"))
	s.Equal(PresenceNever, a.Presence("orphan", SignalSpec{Name: "flow.type", ProducedBy: ProducerAlways}))
}

func (s *AvailabilityTestSuite) TestLoops() {
	// start ─▶ a ─▶ b ─(s)─▶ a ─▶ d : the first visit of a has no s, so s is only sometimes at d.
	sometimes := Initialize().Availability(FlowGraph{Start: "start", Nodes: []GraphNode{
		{ID: "start", Edges: []GraphEdge{edge("a")}},
		{ID: "a", Edges: []GraphEdge{edge("b"), edge("d")}},
		{ID: "b", Edges: []GraphEdge{edge("a", "s")}},
		{ID: "d"},
	}})
	// start ─(s)─▶ a ⇄ b, a ─▶ d : every path has passed the edge that produces s.
	always := Initialize().Availability(FlowGraph{Start: "start", Nodes: []GraphNode{
		{ID: "start", Edges: []GraphEdge{edge("a", "s")}},
		{ID: "a", Edges: []GraphEdge{edge("b"), edge("d")}},
		{ID: "b", Edges: []GraphEdge{edge("a")}},
		{ID: "d"},
	}})

	s.Equal(PresenceSometimes, sometimes.Presence("d", produced("s")))
	s.Equal(PresenceAlways, always.Presence("d", produced("s")))
}

func (s *AvailabilityTestSuite) TestALoopBackToTheStart() {
	a := Initialize().Availability(FlowGraph{Start: "start", Nodes: []GraphNode{
		{ID: "start", Edges: []GraphEdge{edge("retry")}},
		{ID: "retry", Edges: []GraphEdge{edge("start", "s")}},
	}})

	s.Equal(PresenceSometimes, a.Presence("start", produced("s")), "the start has nothing on its first visit")
	s.Equal(PresenceSometimes, a.Presence("retry", produced("s")))
}

func (s *AvailabilityTestSuite) TestEdgesToMissingNodesAndAMissingStart() {
	a := Initialize().Availability(FlowGraph{Start: "start", Nodes: []GraphNode{
		{ID: "start", Edges: []GraphEdge{edge("nowhere", "s"), edge("end")}},
		{ID: "end", End: true},
	}})
	none := Initialize().Availability(FlowGraph{Start: "missing", Nodes: []GraphNode{{ID: "end", End: true}}})

	s.Equal(PresenceNever, a.Presence("end", produced("s")))
	s.False(none.Reachable("end"))
	s.Nil(none.SignalsAtEveryEnd())
}

func (s *AvailabilityTestSuite) TestSignalsAtEveryEnd() {
	// A called flow ends twice: once after identifying the user, once after authenticating them.
	a := Initialize().Availability(FlowGraph{Start: "start", Nodes: []GraphNode{
		{ID: "start", Edges: []GraphEdge{edge("identify")}},
		{ID: "identify", Edges: []GraphEdge{edge("end_identified", SignalUserID), edge("login", SignalUserID)}},
		{ID: "login", Edges: []GraphEdge{
			edge("end_authenticated", SignalUserAuthenticated, SignalSessionAuthTime),
		}},
		{ID: "end_identified", End: true},
		{ID: "end_authenticated", End: true},
		{ID: "unreachable_end", End: true},
	}})
	never := Initialize().Availability(FlowGraph{Start: "start", Nodes: []GraphNode{
		{ID: "start", Edges: []GraphEdge{edge("start", "s")}},
	}})

	s.Equal([]string{SignalUserID}, a.SignalsAtEveryEnd())
	s.Nil(never.SignalsAtEveryEnd())
}

func (s *AvailabilityTestSuite) TestManySignals() {
	nodes := []GraphNode{{ID: "start"}}
	var names []string
	for i := range 130 {
		name := "s" + strconv.Itoa(i)
		names = append(names, name)
		nodes[0].Edges = append(nodes[0].Edges, edge("d", name))
	}
	nodes = append(nodes, GraphNode{ID: "d"})
	a := Initialize().Availability(FlowGraph{Start: "start", Nodes: nodes})

	for _, name := range names {
		s.Equal(PresenceSometimes, a.Presence("d", produced(name)), name)
	}
}

// refReachable lists the nodes reachable from the start using only the edges the filter keeps.
func refReachable(g FlowGraph, from []string, keep func(GraphEdge) bool) map[string]bool {
	byID := map[string]GraphNode{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	seen := map[string]bool{}
	queue := slices.Clone(from)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if _, exists := byID[id]; !exists || seen[id] {
			continue
		}
		seen[id] = true
		for _, e := range byID[id].Edges {
			if keep(e) {
				queue = append(queue, e.To)
			}
		}
	}
	return seen
}

// refPresence decides presence from the definitions: a signal is on every path to a node when the node
// cannot be reached without taking an edge that produces it, and on some path when an edge that produces
// it is reachable and leads on to the node.
func refPresence(g FlowGraph, node, signal string) Presence {
	all := refReachable(g, []string{g.Start}, func(GraphEdge) bool { return true })
	if !all[node] {
		return PresenceNever
	}
	without := refReachable(g, []string{g.Start}, func(e GraphEdge) bool {
		return !slices.Contains(e.Produces, signal)
	})
	if !without[node] {
		return PresenceAlways
	}
	var after []string
	for _, n := range g.Nodes {
		for _, e := range n.Edges {
			if all[n.ID] && slices.Contains(e.Produces, signal) {
				after = append(after, e.To)
			}
		}
	}
	if refReachable(g, after, func(GraphEdge) bool { return true })[node] {
		return PresenceSometimes
	}
	return PresenceNever
}

// randomGraph builds a graph of up to eight nodes with loops and a few signals on random edges.
func randomGraph(rnd *rand.Rand) FlowGraph {
	n := 2 + rnd.IntN(7)
	g := FlowGraph{Start: "n0"}
	for i := range n {
		node := GraphNode{ID: "n" + strconv.Itoa(i), End: rnd.IntN(4) == 0}
		for range rnd.IntN(3) {
			e := GraphEdge{To: "n" + strconv.Itoa(rnd.IntN(n+1))}
			for _, signal := range []string{"a", "b", "c"} {
				if rnd.IntN(3) == 0 {
					e.Produces = append(e.Produces, signal)
				}
			}
			node.Edges = append(node.Edges, e)
		}
		g.Nodes = append(g.Nodes, node)
	}
	return g
}

func (s *AvailabilityTestSuite) TestMatchesTheDefinitionOnRandomGraphs() {
	rnd := rand.New(rand.NewPCG(7, 11))
	for range 3000 {
		g := randomGraph(rnd)
		a := Initialize().Availability(g)
		for _, node := range g.Nodes {
			for _, signal := range []string{"a", "b", "c"} {
				s.Require().Equal(refPresence(g, node.ID, signal), a.Presence(node.ID, produced(signal)),
					node.ID+" "+signal)
			}
		}
	}
}
