// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
)

// SignalRegistryInterface is the set of signals the rules of one scope can use. It resolves signal
// names for the compiler, lists the signals for clients, and fingerprints them so that a compiled plan
// can tell when its signals have changed.
type SignalRegistryInterface interface {
	SignalCatalogInterface
	// Signals lists every signal by name, with each family as one template.
	Signals() []SignalSpec
	// Fingerprint identifies the grammar and the signals; it changes when either does.
	Fingerprint() string
	// rejection reports why a name that looks like a signal of this scope is not one.
	rejection(name string) (DiagnosticCode, bool)
}

// SignalScope is what decides which signals a decision node can use: the flow type, the user types of
// the flow's organization unit, and the prompt inputs and extension steps of the flow.
type SignalScope struct {
	FlowType       string
	UserTypes      []UserTypeSchema
	Inputs         []FlowInput
	ExtensionSteps []ExtensionStep
}

// UserTypeSchema is the part of a user type schema that becomes signals.
type UserTypeSchema struct {
	Name       string
	Attributes []SchemaAttribute
}

// SchemaAttribute is one top-level attribute of a user type schema. ItemType is the type of an array's
// items.
type SchemaAttribute struct {
	Name       string
	Display    string
	Type       string
	ItemType   string
	Credential bool
}

// FlowInput is an input of a prompt in the flow. Credential marks an input mapped to a credential
// attribute.
type FlowInput struct {
	Identifier string
	Type       string
	Credential bool
}

// ExtensionStep is an extension step of the flow: the response fields it stores, and how the outputs
// property describes them.
type ExtensionStep struct {
	NodeID       string
	ResponseKeys []string
	Outputs      map[string]ExtensionOutput
}

// ExtensionOutput describes one stored response field of an extension step.
type ExtensionOutput struct {
	Display     string
	Comparator  string
	Sensitivity string
}

// signalRegistry implements SignalRegistryInterface for one scope.
type signalRegistry struct {
	exact       map[string]SignalSpec
	families    []family
	rejected    map[string]DiagnosticCode
	fingerprint string
	diagnostics []Diagnostic
}

// newSignalRegistry builds the signals of a scope: the built-in layer, the schema layer and the flow
// layer, in that order. A name an earlier layer declares is never redeclared by a later one, so no
// schema attribute or extension field can stand in for a built-in signal.
func newSignalRegistry(scope SignalScope) *signalRegistry {
	r := &signalRegistry{exact: map[string]SignalSpec{}, rejected: map[string]DiagnosticCode{}}
	for _, f := range builtInFamilies() {
		if inFlowType(f.spec, scope.FlowType) {
			r.families = append(r.families, f)
		}
	}
	for _, spec := range builtInSignals {
		spec.Layer = SignalLayerBuiltIn
		r.declare(spec, scope.FlowType)
	}
	for _, spec := range schemaSignals(scope.UserTypes) {
		r.declare(spec, scope.FlowType)
	}
	for _, spec := range inputSignals(scope.Inputs) {
		r.declare(spec, scope.FlowType)
	}
	for _, step := range slices.SortedFunc(slices.Values(scope.ExtensionSteps), func(a, b ExtensionStep) int {
		return cmp.Compare(a.NodeID, b.NodeID)
	}) {
		r.extension(step, scope.FlowType)
	}
	r.fingerprint = fingerprintOf(r.Signals())
	return r
}

// declare adds a signal unless a signal of that name, or a family it belongs to, already exists, or it
// is not for the flow type.
func (r *signalRegistry) declare(spec SignalSpec, flowType string) {
	if _, exists := r.Lookup(spec.Name); exists || !inFlowType(spec, flowType) {
		return
	}
	r.exact[spec.Name] = spec
}

// extension declares the signals of an extension step's stored fields and checks its outputs property.
// A field whose name, with the node ID, does not form a valid signal name is not a signal; a rule that
// uses it is told why.
func (r *signalRegistry) extension(step ExtensionStep, flowType string) {
	outputsPath := join(fieldProperties, fieldOutputs)
	for _, field := range slices.Sorted(maps.Keys(step.Outputs)) {
		if !slices.Contains(step.ResponseKeys, field) {
			r.add(step.NodeID, join(outputsPath, field), CodeOutputNotStored, map[string]string{paramName: field})
		}
	}
	validID := isIdentifier(step.NodeID, true)
	for _, field := range step.ResponseKeys {
		name := prefixExtension + step.NodeID + nameSeparator + field
		if !validID || !isIdentifier(field, false) {
			r.rejected[name] = CodeOutputName
			continue
		}
		spec := SignalSpec{
			Name: name, Display: field, Category: SignalCategoryRuntime, Layer: SignalLayerFlow,
			Trust: TrustExternal, Sensitivity: SensitivityInternal, ProducedBy: ProducerExtension,
		}
		if output, described := step.Outputs[field]; described {
			r.describe(&spec, output, step.NodeID, join(outputsPath, field))
		}
		r.declare(spec, flowType)
	}
}

// describe applies an outputs entry to the signal of a stored field, reporting a comparator or a
// sensitivity that does not exist. A scale cannot be declared here, because it needs its members.
func (r *signalRegistry) describe(spec *SignalSpec, output ExtensionOutput, nodeID, path string) {
	if output.Display != "" {
		spec.Display = output.Display
	}
	if output.Comparator != "" {
		comparator := comparatorByName(ComparatorName(output.Comparator))
		if comparator == cmpNone || comparator == cmpScale {
			r.add(nodeID, join(path, fieldComparator), CodeOutputDeclaration,
				map[string]string{paramValue: output.Comparator})
		} else {
			spec.Comparator = comparator.displayName()
		}
	}
	if output.Sensitivity != "" {
		sensitivity := Sensitivity(output.Sensitivity)
		if sensitivityRank(sensitivity) < 0 {
			r.add(nodeID, join(path, fieldSensitivity), CodeOutputDeclaration,
				map[string]string{paramValue: output.Sensitivity})
		} else {
			spec.Sensitivity = sensitivity
		}
	}
}

// add records a diagnostic about a node of the flow.
func (r *signalRegistry) add(nodeID, path string, code DiagnosticCode, params map[string]string) {
	d := newDiagnostic(path, code, params)
	d.NodeID = nodeID
	r.diagnostics = append(r.diagnostics, d)
}

// Lookup returns the signal a name denotes: a declared signal, or a member of a family.
func (r *signalRegistry) Lookup(name string) (SignalSpec, bool) {
	if spec, ok := r.exact[name]; ok {
		return spec, true
	}
	for i := range r.families {
		if spec, ok := r.families[i].member(name); ok {
			return spec, true
		}
	}
	return SignalSpec{}, false
}

// Signals lists every declared signal and every family template, sorted by name.
func (r *signalRegistry) Signals() []SignalSpec {
	specs := slices.Collect(maps.Values(r.exact))
	for _, f := range r.families {
		specs = append(specs, f.spec)
	}
	slices.SortFunc(specs, func(a, b SignalSpec) int { return cmp.Compare(a.Name, b.Name) })
	return specs
}

// Fingerprint identifies the grammar version, the operators and the signals of the registry.
func (r *signalRegistry) Fingerprint() string {
	return r.fingerprint
}

// rejection reports why a name that looks like an extension step's field is not a signal.
func (r *signalRegistry) rejection(name string) (DiagnosticCode, bool) {
	code, ok := r.rejected[name]
	return code, ok
}

// fingerprintOf hashes the grammar version, the operator names and the signals.
func fingerprintOf(signals []SignalSpec) string {
	names := make([]string, len(operators))
	for i := range operators {
		names[i] = operators[i].name
	}
	encoded, _ := json.Marshal(struct {
		Grammar   int          `json:"grammar"`
		Operators []string     `json:"operators"`
		Signals   []SignalSpec `json:"signals"`
	}{grammarVersionCurrent, names, signals})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// inFlowType reports whether a signal exists in flows of the given type. A signal that names no flow
// type exists in all of them, and so does every signal when the flow type is not known.
func inFlowType(spec SignalSpec, flowType string) bool {
	return len(spec.FlowTypes) == 0 || flowType == "" || slices.Contains(spec.FlowTypes, flowType)
}

// schemaSignals generates user.<attribute> for every attribute of the user types that can be compared:
// strings and contact attributes as text, numbers, booleans, and arrays of those. Credential attributes,
// objects, and attributes whose name cannot form a signal name are left out. When user types disagree
// on how an attribute is read, its comparator is left to inference.
func schemaSignals(userTypes []UserTypeSchema) []SignalSpec {
	merged := map[string]SignalSpec{}
	byName := func(a, b UserTypeSchema) int { return cmp.Compare(a.Name, b.Name) }
	for _, userType := range slices.SortedFunc(slices.Values(userTypes), byName) {
		for _, attr := range userType.Attributes {
			if attr.Credential || !isIdentifier(attr.Name, false) {
				continue
			}
			comparator, multi, ok := schemaReading(attr.Type, attr.ItemType)
			if !ok {
				continue
			}
			spec := SignalSpec{
				Name: prefixUser + attr.Name, Display: cmp.Or(attr.Display, attr.Name), Category: SignalCategoryUser,
				Layer: SignalLayerSchema, Comparator: comparator, Multi: multi, CostClass: CostStore,
				Trust: TrustDirectory, Sensitivity: schemaSensitivity(attr), ProducedBy: ProducerExecutor,
				With: SignalUserID, AccountData: true,
			}
			merged[spec.Name] = mergeSignals(merged, spec)
		}
	}
	return slices.Collect(maps.Values(merged))
}

// schemaReading returns how an attribute of a schema type is read, and whether it can be at all.
func schemaReading(attrType, itemType string) (ComparatorName, bool, bool) {
	switch attrType {
	case schemaTypeString, schemaTypeEmail, schemaTypeMobile:
		return ComparatorText, false, true
	case schemaTypeNumber:
		return ComparatorNumber, false, true
	case schemaTypeBoolean:
		return ComparatorBoolean, false, true
	case schemaTypeArray:
		if itemType == schemaTypeArray {
			return "", false, false
		}
		comparator, _, ok := schemaReading(itemType, "")
		return comparator, true, ok
	}
	return "", false, false
}

// schemaSensitivity marks contact attributes as personal data.
func schemaSensitivity(attr SchemaAttribute) Sensitivity {
	for _, t := range []string{attr.Type, attr.ItemType} {
		if t == schemaTypeEmail || t == schemaTypeMobile {
			return SensitivityPII
		}
	}
	return SensitivityInternal
}

// inputSignals generates input.<identifier> for every prompt input that is not a secret: password and
// OTP inputs, and inputs mapped to credentials, are left out. A number input is read as a number and
// every other input as text.
func inputSignals(inputs []FlowInput) []SignalSpec {
	merged := map[string]SignalSpec{}
	for _, input := range inputs {
		if input.Credential || input.Type == inputTypePassword || input.Type == inputTypeOTP ||
			!isIdentifier(input.Identifier, false) {
			continue
		}
		spec := SignalSpec{
			Name: prefixInput + input.Identifier, Display: input.Identifier, Category: SignalCategoryUserCollected,
			Layer: SignalLayerFlow, Comparator: ComparatorText, Trust: TrustSubject,
			Sensitivity: SensitivityInternal, ProducedBy: ProducerInput,
		}
		if input.Type == inputTypeNumber {
			spec.Comparator = ComparatorNumber
		}
		if input.Type == inputTypeEmail || input.Type == inputTypePhone {
			spec.Sensitivity = SensitivityPII
		}
		merged[spec.Name] = mergeSignals(merged, spec)
	}
	return slices.Collect(maps.Values(merged))
}

// mergeSignals combines a signal with an earlier declaration of the same name: a comparator they
// disagree on is dropped, and the signal is multi-valued and sensitive if either is.
func mergeSignals(merged map[string]SignalSpec, spec SignalSpec) SignalSpec {
	earlier, ok := merged[spec.Name]
	if !ok {
		return spec
	}
	if earlier.Comparator != spec.Comparator {
		earlier.Comparator = ""
	}
	earlier.Multi = earlier.Multi || spec.Multi
	if sensitivityRank(spec.Sensitivity) > sensitivityRank(earlier.Sensitivity) {
		earlier.Sensitivity = spec.Sensitivity
	}
	return earlier
}

// sensitivityRank orders sensitivities, least sensitive first.
func sensitivityRank(s Sensitivity) int {
	return slices.Index([]Sensitivity{SensitivityPublic, SensitivityInternal, SensitivityPII}, s)
}
