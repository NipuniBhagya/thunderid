// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package executormeta

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// declares reports whether the outputs include the signal on completion in exactly the given modes.
func declares(outputs []providers.ExecutorOutput, signal string, modes []string) bool {
	return slices.ContainsFunc(outputs, func(o providers.ExecutorOutput) bool {
		return o.Signal == signal && o.OnStatus == providers.ExecComplete && slices.Equal(o.Modes, modes)
	})
}

// declaresSignal reports whether the outputs include the signal at all.
func declaresSignal(outputs []providers.ExecutorOutput, signal string) bool {
	return slices.ContainsFunc(outputs, func(o providers.ExecutorOutput) bool { return o.Signal == signal })
}

// Every executor that proves who the user is declares both the user and that they authenticated, and
// only in the modes that prove it: a step that sends a code or a link also completes (AC6.6).
func TestAuthenticatingExecutorsDeclareTheUserAndAuthentication(t *testing.T) {
	authenticating := map[string][]string{
		ExecutorNameCredentialsAuth: nil,
		ExecutorNamePasskeyAuth:     {ExecutorModeVerify},
		ExecutorNameMagicLink:       {ExecutorModeVerify},
		ExecutorNameOTPExecutor:     {ExecutorModeVerify},
		ExecutorNameOAuth:           nil,
		ExecutorNameOIDCAuth:        nil,
		ExecutorNameGitHubAuth:      nil,
		ExecutorNameGoogleAuth:      nil,
		ExecutorNameOpenID4VPVerify: nil,
		ExecutorNameSSOCheck:        nil,
	}
	for name, modes := range authenticating {
		meta, ok := MetaFor(name)
		require.True(t, ok, name)

		assert.True(t, declares(meta.Outputs, SignalUserID, modes), name)
		assert.True(t, declares(meta.Outputs, SignalUserAuthenticated, modes), name)
	}
}

// An executor that only finds or creates the account declares the user but not authentication, so a
// rule that reads the account before authentication is flagged.
func TestIdentifyingExecutorsDeclareOnlyTheUser(t *testing.T) {
	identifying := map[string][]string{
		ExecutorNameIdentifying:  {ExecutorModeIdentify, ExecutorModeResolve},
		ExecutorNameProvisioning: nil,
	}
	for name, modes := range identifying {
		meta, ok := MetaFor(name)
		require.True(t, ok, name)

		assert.True(t, declares(meta.Outputs, SignalUserID, modes), name)
		assert.False(t, declaresSignal(meta.Outputs, SignalUserAuthenticated), name)
	}
}

func TestSessionStepsDeclareTheSessionAuthTime(t *testing.T) {
	for _, name := range []string{ExecutorNameSession, ExecutorNameSSOCheck} {
		meta, ok := MetaFor(name)
		require.True(t, ok, name)

		assert.True(t, declares(meta.Outputs, SignalSessionAuthTime, nil), name)
	}
}

// Outputs name only the signals executors can produce, on completion, in modes the executor has, and
// authentication never appears without the user it is about.
func TestEveryDeclaredOutputIsWellFormed(t *testing.T) {
	known := []string{SignalUserID, SignalUserAuthenticated, SignalSessionAuthTime}
	for _, name := range Names() {
		meta, _ := MetaFor(name)
		for _, o := range meta.Outputs {
			assert.Contains(t, known, o.Signal, name)
			assert.Equal(t, providers.ExecComplete, o.OnStatus, name)
			for _, mode := range o.Modes {
				assert.Contains(t, meta.SupportedModes, mode, name)
			}
			if o.Signal == SignalUserAuthenticated {
				assert.True(t, declares(meta.Outputs, SignalUserID, o.Modes), name)
			}
		}
	}
}

func TestReturnedMetadataDoesNotAliasOutputs(t *testing.T) {
	meta, ok := MetaFor(ExecutorNameOTPExecutor)
	require.True(t, ok)
	require.NotEmpty(t, meta.Outputs)

	meta.Outputs[0].Signal = "mutated-by-caller"
	meta.Outputs[0].Modes[0] = "mutated-by-caller"

	again, _ := MetaFor(ExecutorNameOTPExecutor)
	assert.Equal(t, SignalUserID, again.Outputs[0].Signal)
	assert.Equal(t, ExecutorModeVerify, again.Outputs[0].Modes[0])
}

func TestOutputHelpersDoNotShareModes(t *testing.T) {
	modes := []string{ExecutorModeVerify}
	outputs := AuthenticatesUser(modes...)

	outputs[0].Modes[0] = "mutated-by-caller"

	assert.Equal(t, ExecutorModeVerify, outputs[1].Modes[0])
	assert.Equal(t, ExecutorModeVerify, modes[0])
	assert.Nil(t, IdentifiesUser()[0].Modes, "no modes means every mode")
}

func TestExtensionStepsAcceptOutputs(t *testing.T) {
	meta, ok := MetaFor(ExecutorNameExtension)
	require.True(t, ok)

	assert.True(t, slices.ContainsFunc(meta.SupportedProperties, func(p providers.ExecutorSupportedProperties) bool {
		return p.Property == "outputs"
	}))
}
