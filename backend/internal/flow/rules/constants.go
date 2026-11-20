// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package rules

// Grammar and hit policy.
const (
	// grammarVersionCurrent is the rule grammar this engine understands.
	grammarVersionCurrent = 1
	// HitPolicyFirst evaluates rules in author order; the first rule that is not false decides.
	HitPolicyFirst HitPolicy = "FIRST"
)

// Default and maximum limits on the size of a decision block.
const (
	defaultMaxRules     = 32
	defaultMaxDepth     = 6
	defaultMaxLeaves    = 128
	defaultMaxTests     = 32
	maxListSizeCap      = 1000
	hardCapMaxRules     = 64
	hardCapMaxDepth     = 8
	hardCapMaxLeaves    = 256
	hardCapMaxTests     = 64
	maxRuleIDLength     = 64
	maxLabelLength      = 200
	maxDurationDigits   = 9
	hashSetMinListSize  = 8
	nominalDaysPerYear  = 365
	nominalDaysPerMonth = 30
	secondsPerDay       = 86400
	secondsPerHour      = 3600
	secondsPerMinute    = 60
	daysPerWeek         = 7
	isoDateLength       = 10
)

// Field names of the decision block, as they appear in its JSON form.
const (
	fieldGrammarVersion  = "grammarVersion"
	fieldHitPolicy       = "hitPolicy"
	fieldRules           = "rules"
	fieldDefault         = "default"
	fieldUnknown         = "unknown"
	fieldTests           = "tests"
	fieldSource          = "source"
	fieldID              = "id"
	fieldLabel           = "label"
	fieldWhen            = "when"
	fieldNextNode        = "nextNode"
	fieldOp              = "op"
	fieldSignal          = "signal"
	fieldValue           = "value"
	fieldRef             = "ref"
	fieldCI              = "ci"
	fieldEvery           = "every"
	fieldOptions         = "options"
	fieldOf              = "of"
	fieldName            = "name"
	fieldFacts           = "facts"
	fieldUnresolved      = "unresolved"
	fieldContext         = "context"
	fieldExpect          = "expect"
	fieldFrontend        = "frontend"
	fieldFrontendVersion = "frontendVersion"
	fieldFlowType        = "flowType"
	fieldApplicationID   = "applicationId"
	fieldOUID            = "ouId"
)

// Operator names.
const (
	opEq         = "eq"
	opGt         = "gt"
	opGte        = "gte"
	opStartsWith = "startsWith"
	opEndsWith   = "endsWith"
	opContains   = "contains"
	opOlderThan  = "olderThan"
	opExists     = "exists"
	opIsEmpty    = "isEmpty"
	opAll        = "all"
	opAny        = "any"
	opNot        = "not"
)

// Diagnostic codes.
const (
	// CodeSyntax reports a value of the wrong JSON type, or a decision block that is not valid JSON.
	CodeSyntax DiagnosticCode = "E_SYNTAX"
	// CodeUnknownField reports a field the grammar does not define.
	CodeUnknownField DiagnosticCode = "E_UNKNOWN_FIELD"
	// CodeMissingField reports a required field that is absent or empty.
	CodeMissingField DiagnosticCode = "E_MISSING_FIELD"
	// CodeGrammarVersion reports a grammar version this engine does not support.
	CodeGrammarVersion DiagnosticCode = "E_GRAMMAR_VERSION"
	// CodeHitPolicy reports a hit policy this engine does not support.
	CodeHitPolicy DiagnosticCode = "E_HIT_POLICY"
	// CodeInvalidID reports a rule ID that does not match the allowed form.
	CodeInvalidID DiagnosticCode = "E_INVALID_ID"
	// CodeDuplicateRuleID reports two rules with the same ID.
	CodeDuplicateRuleID DiagnosticCode = "E_DUPLICATE_RULE_ID"
	// CodeNoRules reports a decision with no rules.
	CodeNoRules DiagnosticCode = "E_NO_RULES"
	// CodeMissingArm reports a missing default or unknown arm.
	CodeMissingArm DiagnosticCode = "E_MISSING_ARM"
	// CodeUnknownNode reports a missing nextNode.
	CodeUnknownNode DiagnosticCode = "E_UNKNOWN_NODE"
	// CodeArity reports a group with fewer than two children, or a negation without exactly one.
	CodeArity DiagnosticCode = "E_ARITY"
	// CodeOperand reports a value or ref that the operator does not accept.
	CodeOperand DiagnosticCode = "E_OPERAND"
	// CodeQualifier reports a qualifier that the operator does not accept.
	CodeQualifier DiagnosticCode = "E_QUALIFIER"
	// CodeOptions reports options that the operator does not accept.
	CodeOptions DiagnosticCode = "E_OPTIONS"
	// CodeUnknownOperator reports an operator that is not registered.
	CodeUnknownOperator DiagnosticCode = "E_UNKNOWN_OPERATOR"
	// CodeUnknownSignal reports a signal that is not declared.
	CodeUnknownSignal DiagnosticCode = "E_UNKNOWN_SIGNAL"
	// CodeLimit reports a limit that is exceeded.
	CodeLimit DiagnosticCode = "E_LIMIT"
	// CodeIncomparableLiteral reports a literal the signal's declared comparator cannot read.
	CodeIncomparableLiteral DiagnosticCode = "W_INCOMPARABLE_LITERAL"
	// CodeOperatorComparator reports an operator whose needs the signal's declared comparator cannot meet.
	CodeOperatorComparator DiagnosticCode = "W_OPERATOR_COMPARATOR"
	// CodeOutputName reports a rule that uses an extension step's field whose node ID or field name does
	// not form a valid signal name.
	CodeOutputName DiagnosticCode = "E_OUTPUT_NAME"
	// CodeOutputNotStored reports an outputs entry for a field the extension step does not store.
	CodeOutputNotStored DiagnosticCode = "E_OUTPUT_NOT_STORED"
	// CodeOutputDeclaration reports an outputs entry that names a comparator or sensitivity that does
	// not exist.
	CodeOutputDeclaration DiagnosticCode = "E_OUTPUT_DECLARATION"
	// CodeSignalUnavailable reports a signal that exists on no path into the decision node.
	CodeSignalUnavailable DiagnosticCode = "E_SIGNAL_UNAVAILABLE"
	// CodeSignalSometimesAbsent reports a signal that exists on some paths into the node only; on the
	// others the rule is unknown and the unknown arm decides.
	CodeSignalSometimesAbsent DiagnosticCode = "W_SIGNAL_SOMETIMES_ABSENT"
	// CodeUnauthenticatedUser reports a rule that reads the identified account's directory data where
	// the user has not authenticated on every path into the node.
	CodeUnauthenticatedUser DiagnosticCode = "W_UNAUTHENTICATED_USER"
	// CodeSubjectTrust reports a rule whose condition reads only values the user or the client supplied.
	CodeSubjectTrust DiagnosticCode = "W_SUBJECT_TRUST"
	// CodeNeverTrue reports a rule whose condition can never be true.
	CodeNeverTrue DiagnosticCode = "W_NEVER_TRUE"
	// CodeShadowedRule reports a rule that can never decide, because an earlier rule always does.
	CodeShadowedRule DiagnosticCode = "W_SHADOWED_RULE"
	// CodeTestFailed reports a node test whose outcome differs from what it expects.
	CodeTestFailed DiagnosticCode = "E_TEST_FAILED"
)

// Diagnostic parameter names.
const (
	paramField    = "field"
	paramExpected = "expected"
	paramLimit    = "limit"
	paramName     = "name"
	paramValue    = "value"
	paramActual   = "actual"
	paramRuleID   = "ruleId"
)

// Expected JSON types, used as diagnostic parameters.
const (
	typeObject  = "object"
	typeArray   = "array"
	typeString  = "string"
	typeInteger = "integer"
	typeBoolean = "boolean"
	typeLiteral = "string, number, boolean or a non-empty list of them"
)

// Names of the cost classes, as clients see them.
const (
	costLocal  = "local"
	costStore  = "store"
	costRemote = "remote"
)

// Built-in signals and signal families.
const (
	signalFlowType        = "flow.type"
	signalApplicationID   = "application.id"
	signalApplicationName = "application.name"
	signalApplicationType = "application.type"
	signalApplicationOUID = "application.ouId"
	// SignalUserID is the identified user. Executors declare it when they identify or authenticate one.
	SignalUserID = "user.id"
	// SignalUserAuthenticated is true once the identified user has authenticated. Executors declare it
	// when they verify a credential, a federated login or an existing session.
	SignalUserAuthenticated = "user.authenticated"
	signalUserOUID          = "user.ouId"
	signalUserType          = "user.type"
	signalUserGroups        = "user.groups"
	// SignalSessionAuthTime is when the user of the session last authenticated.
	SignalSessionAuthTime = "session.authTime"
	familyRequestHeader   = "request.header."
	familyRequestQuery    = "request.query."
	familyInitialHeader   = "request.initial.header."
	familyInitialQuery    = "request.initial.query."
)

// Prefixes of generated signals, and the separator inside signal names.
const (
	prefixUser      = "user."
	prefixInput     = "input."
	prefixExtension = "extension."
	nameSeparator   = "."
)

// Bounds on the parts of a generated or family signal name.
const (
	maxNameSegmentLength  = 128
	maxFamilySuffixLength = 256
)

// Types of user type schema attributes that become signals.
const (
	schemaTypeString  = "string"
	schemaTypeEmail   = "email"
	schemaTypeMobile  = "mobile"
	schemaTypeNumber  = "number"
	schemaTypeBoolean = "boolean"
	schemaTypeArray   = "array"
)

// Prompt input types the signal registry treats specially. They match the input types of the flow
// definition.
const (
	inputTypeNumber   = "NUMBER_INPUT"
	inputTypeEmail    = "EMAIL_INPUT"
	inputTypePhone    = "PHONE_INPUT"
	inputTypePassword = "PASSWORD_INPUT"
	inputTypeOTP      = "OTP_INPUT"
)

// Paths of an extension step's outputs, for diagnostics about them.
const (
	fieldProperties  = "properties"
	fieldOutputs     = "outputs"
	fieldComparator  = "comparator"
	fieldSensitivity = "sensitivity"
)
