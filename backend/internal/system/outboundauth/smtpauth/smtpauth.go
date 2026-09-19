// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

// Package smtpauth binds an outbound authentication configuration to the SASL mechanism
// net/smtp expects. It is the SMTP half of the outboundauth seam: outboundauth itself stays
// transport-neutral, and nothing here is reachable from another transport.
package smtpauth

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/thunder-id/thunderid/internal/system/outboundauth"
)

// Authenticator produces the SASL mechanism for an SMTP session.
type Authenticator interface {
	// Auth returns the mechanism to present to the server, or a nil smtp.Auth when the
	// configuration authenticates nothing, so a caller can hand the result straight to
	// smtp.Client.Auth after a nil check. host is the server name the credentials are bound to.
	Auth(ctx context.Context, host string) (smtp.Auth, error)
}

// basicAuthenticator presents SASL PLAIN.
type basicAuthenticator struct {
	username string
	password string
}

// noopAuthenticator presents nothing.
type noopAuthenticator struct{}

// New returns the Authenticator for cfg. It is built once per client, so a method that has to
// acquire and cache a token has somewhere to keep it. An error means cfg names a method SMTP
// cannot carry, which validation should already have refused.
func New(cfg outboundauth.Config) (Authenticator, error) {
	authType := cfg.Type
	if authType == "" {
		authType = outboundauth.TypeNone
	}

	switch authType {
	case outboundauth.TypeNone:
		return &noopAuthenticator{}, nil
	case outboundauth.TypeBasic:
		return &basicAuthenticator{
			username: cfg.Get(outboundauth.FieldBasicUsername),
			password: cfg.Get(outboundauth.FieldBasicPassword),
		}, nil
	default:
		return nil, fmt.Errorf("authentication type is not supported over SMTP: %s", authType)
	}
}

// Auth returns the PLAIN mechanism bound to host.
func (a *basicAuthenticator) Auth(_ context.Context, host string) (smtp.Auth, error) {
	return smtp.PlainAuth("", a.username, a.password, host), nil
}

// Auth returns a nil mechanism, signaling that no credentials are presented.
func (a *noopAuthenticator) Auth(_ context.Context, _ string) (smtp.Auth, error) {
	return nil, nil
}
