// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package smtpauth

import (
	"context"
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/outboundauth"
)

type SMTPAuthTestSuite struct {
	suite.Suite
}

func TestSMTPAuthTestSuite(t *testing.T) {
	suite.Run(t, new(SMTPAuthTestSuite))
}

func (s *SMTPAuthTestSuite) TestBasicPresentsPlainMechanism() {
	authenticator, err := New(outboundauth.Config{
		Type: outboundauth.TypeBasic,
		Properties: map[string]string{
			outboundauth.FieldBasicUsername: "mailer",
			outboundauth.FieldBasicPassword: "s3cret",
		},
	})
	s.Require().NoError(err)

	auth, err := authenticator.Auth(context.Background(), "smtp.example.com")
	s.Require().NoError(err)
	s.Require().NotNil(auth)

	mechanism, response, err := auth.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: true})
	s.Require().NoError(err)
	s.Equal("PLAIN", mechanism)
	s.Equal("\x00mailer\x00s3cret", string(response))
}

func (s *SMTPAuthTestSuite) TestBasicIsBoundToTheHost() {
	authenticator, err := New(outboundauth.Config{
		Type: outboundauth.TypeBasic,
		Properties: map[string]string{
			outboundauth.FieldBasicUsername: "mailer",
			outboundauth.FieldBasicPassword: "s3cret",
		},
	})
	s.Require().NoError(err)

	auth, err := authenticator.Auth(context.Background(), "smtp.example.com")
	s.Require().NoError(err)

	// PlainAuth refuses to hand credentials to a server it was not bound to, which is what
	// stops a redirected or spoofed connection from collecting them.
	_, _, err = auth.Start(&smtp.ServerInfo{Name: "evil.example.com", TLS: true})
	s.Require().Error(err)
}

func (s *SMTPAuthTestSuite) TestNoneAndZeroConfigPresentNothing() {
	for _, cfg := range []outboundauth.Config{{Type: outboundauth.TypeNone}, {}} {
		authenticator, err := New(cfg)
		s.Require().NoError(err)

		auth, err := authenticator.Auth(context.Background(), "smtp.example.com")
		s.Require().NoError(err)
		s.Nil(auth)
	}
}

func (s *SMTPAuthTestSuite) TestUnsupportedTypeIsRejected() {
	_, err := New(outboundauth.Config{Type: outboundauth.Type("bearer")})
	s.Require().Error(err)
	s.Contains(err.Error(), "not supported over SMTP")
}
