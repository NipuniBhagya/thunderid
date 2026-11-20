// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"unicode"
)

// builtInSignals declares the signals that exist in every flow, as the platform defines them. The
// user's type, groups and organization unit exist wherever the user does, so they follow user.id.
var builtInSignals = []SignalSpec{
	{
		Name: signalFlowType, Display: "Flow type", Description: "The type of the running flow.",
		Category: SignalCategoryApplication, Trust: TrustSystem, Sensitivity: SensitivityPublic,
		ProducedBy: ProducerAlways,
	},
	{
		Name: signalApplicationID, Display: "Application ID", Description: "The application that started the flow.",
		Category: SignalCategoryApplication, Trust: TrustSystem, Sensitivity: SensitivityPublic,
		ProducedBy: ProducerAlways,
	},
	{
		Name: signalApplicationName, Display: "Application name",
		Description: "The name of the application that started the flow.",
		Category:    SignalCategoryApplication, Trust: TrustSystem, Sensitivity: SensitivityPublic,
		ProducedBy: ProducerAlways,
	},
	{
		Name: signalApplicationType, Display: "Application type",
		Description: "The type of the application that started the flow.",
		Category:    SignalCategoryApplication, Trust: TrustSystem, Sensitivity: SensitivityPublic,
		ProducedBy: ProducerAlways,
	},
	{
		Name: signalApplicationOUID, Display: "Application organization unit",
		Description: "The organization unit of the application that started the flow.",
		Category:    SignalCategoryApplication, Trust: TrustSystem, Sensitivity: SensitivityInternal,
		ProducedBy: ProducerAlways,
	},
	{
		Name: SignalUserID, Display: "User ID", Description: "The user an earlier step identified.",
		Category: SignalCategoryUser, Trust: TrustSystem, Sensitivity: SensitivityInternal,
		ProducedBy: ProducerExecutor,
	},
	{
		Name: SignalUserAuthenticated, Display: "User authenticated",
		Description: "True once an earlier step has authenticated the identified user.",
		Category:    SignalCategoryUser, Comparator: ComparatorBoolean, Trust: TrustSystem,
		Sensitivity: SensitivityInternal, ProducedBy: ProducerExecutor,
	},
	{
		Name: signalUserOUID, Display: "User organization unit",
		Description: "The organization unit of the identified user.",
		Category:    SignalCategoryUser, Trust: TrustSystem, Sensitivity: SensitivityInternal,
		ProducedBy: ProducerExecutor, With: SignalUserID, AccountData: true,
	},
	{
		Name: signalUserType, Display: "User type", Description: "The user type of the identified user.",
		Category: SignalCategoryUser, CostClass: CostStore, Trust: TrustDirectory, Sensitivity: SensitivityInternal,
		ProducedBy: ProducerExecutor, With: SignalUserID, AccountData: true,
	},
	{
		Name: signalUserGroups, Display: "Groups", Description: "The groups the identified user belongs to.",
		Category: SignalCategoryUser, Multi: true, CostClass: CostStore, Trust: TrustDirectory,
		Sensitivity: SensitivityInternal, ProducedBy: ProducerExecutor, With: SignalUserID, AccountData: true,
	},
	{
		Name: SignalSessionAuthTime, Display: "Authentication time",
		Description: "When the user of the session last authenticated.",
		Category:    SignalCategorySession, Comparator: ComparatorInstant, Trust: TrustSystem,
		Sensitivity: SensitivityInternal, ProducedBy: ProducerExecutor,
	},
}

// family is a template for signals named by a prefix and a suffix the author chooses, such as a header
// name. Header names match whatever their case; query parameter names match exactly.
type family struct {
	spec  SignalSpec
	fold  bool
	valid func(suffix string) bool
}

// builtInFamilies returns the signal families of the request, longest prefix first.
func builtInFamilies() []family {
	request := func(prefix, display, description string, fold bool, valid func(string) bool) family {
		return family{spec: SignalSpec{
			Name: prefix, Display: display, Description: description, Category: SignalCategoryRequest,
			Layer: SignalLayerBuiltIn, Trust: TrustSubject, Sensitivity: SensitivityInternal,
			ProducedBy: ProducerAlways, Family: true,
		}, fold: fold, valid: valid}
	}
	return []family{
		request(familyInitialHeader, "Initial request header",
			"A header of the request that started the flow, named after the prefix.", true, isHeaderName),
		request(familyInitialQuery, "Initial query parameter",
			"A query parameter of the request that started the flow, named after the prefix.", false, isQueryName),
		request(familyRequestHeader, "Request header",
			"A header of the current request, named after the prefix.", true, isHeaderName),
		request(familyRequestQuery, "Query parameter",
			"A query parameter of the current request, named after the prefix.", false, isQueryName),
	}
}

// member returns the signal a name denotes in the family, with a header name folded to lower case so
// that every spelling is the same signal.
func (f *family) member(name string) (SignalSpec, bool) {
	suffix, ok := strings.CutPrefix(name, f.spec.Name)
	if !ok || !f.valid(suffix) {
		return SignalSpec{}, false
	}
	if f.fold {
		suffix = strings.ToLower(suffix)
	}
	spec := f.spec
	spec.Name = f.spec.Name + suffix
	spec.Display = f.spec.Display + " " + suffix
	spec.Family = false
	return spec, true
}

// isHeaderName reports whether s is an HTTP field name: one or more token characters (RFC 9110).
func isHeaderName(s string) bool {
	if s == "" || len(s) > maxFamilySuffixLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlphaNumeric(c) && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

// isQueryName reports whether s can name a query parameter: printable characters other than spaces.
func isQueryName(s string) bool {
	if s == "" || len(s) > maxFamilySuffixLength {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// isIdentifier reports whether s can be one segment of a generated signal name: a letter followed by
// letters, digits and underscores. With lowerOnly, upper case letters are refused, as in a node ID.
func isIdentifier(s string, lowerOnly bool) bool {
	if s == "" || len(s) > maxNameSegmentLength || !isLetter(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (!isAlphaNumeric(c) && c != '_') || (lowerOnly && c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// isLetter reports whether c is an ASCII letter.
func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isAlphaNumeric reports whether c is an ASCII letter or digit.
func isAlphaNumeric(c byte) bool {
	return isLetter(c) || isDigit(c)
}
