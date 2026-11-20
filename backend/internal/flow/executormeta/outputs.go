// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package executormeta

import (
	"slices"

	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// Signals that executors declare as outputs. These are the built-in decision signals that exist only
// after a step has run, so the availability analysis needs to know which steps produce them.
const (
	// SignalUserID is the identified user. Every executor that identifies or authenticates a user
	// declares it.
	SignalUserID = "user.id"
	// SignalUserAuthenticated marks that the identified user has proved who they are. Only an executor
	// that verifies a credential, a federated login or an existing session declares it.
	SignalUserAuthenticated = "user.authenticated"
	// SignalSessionAuthTime is the time the user of the session last authenticated.
	SignalSessionAuthTime = "session.authTime"
)

// IdentifiesUser returns the outputs of an executor that identifies a user without authenticating
// them, on completion in the given modes, or in every mode when none is given.
func IdentifiesUser(modes ...string) []providers.ExecutorOutput {
	return []providers.ExecutorOutput{onComplete(SignalUserID, modes)}
}

// AuthenticatesUser returns the outputs of an executor that authenticates a user, on completion in
// the given modes, or in every mode when none is given. Modes matter: a step that only sends a code
// or a link also completes, and must not make the user look authenticated.
func AuthenticatesUser(modes ...string) []providers.ExecutorOutput {
	return []providers.ExecutorOutput{onComplete(SignalUserID, modes), onComplete(SignalUserAuthenticated, modes)}
}

// RecordsSessionAuthTime returns the output of an executor that records when the session's user
// authenticated.
func RecordsSessionAuthTime() providers.ExecutorOutput {
	return onComplete(SignalSessionAuthTime, nil)
}

// onComplete returns an output that exists when the executor completes in one of the modes.
func onComplete(signal string, modes []string) providers.ExecutorOutput {
	return providers.ExecutorOutput{Signal: signal, OnStatus: providers.ExecComplete, Modes: slices.Clone(modes)}
}
