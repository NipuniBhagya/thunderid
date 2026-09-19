// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package outboundauth

import (
	"fmt"
	"regexp"
	"strings"
)

// Validate checks cfg against the descriptor for its type and the set of types the caller
// supports. It enforces exactly what the descriptors declare: a known and permitted type, a
// non-blank value for every required field, values within any declared enum or pattern, and no
// field the method does not declare. It then runs the method's own rules, if it has any.
//
// Policy that depends on the transport, such as SMTP refusing to send credentials over a
// plaintext connection, belongs to the caller.
func Validate(cfg Config, supported []Type) error {
	authType := cfg.Type
	if authType == "" {
		authType = TypeNone
	}

	if _, ok := Descriptor(authType); !ok {
		return fmt.Errorf("unsupported authentication type: %s", cfg.Type)
	}
	if !containsType(supported, authType) {
		return fmt.Errorf("authentication type is not supported by this provider: %s", authType)
	}

	descriptor, _ := Descriptor(authType)

	for name := range cfg.Properties {
		if _, ok := field(authType, name); !ok {
			return fmt.Errorf("unknown authentication property for type %s: %s", authType, name)
		}
	}

	for _, fieldDescriptor := range descriptor.Fields {
		if err := validateField(fieldDescriptor, cfg.Get(fieldDescriptor.Name), authType); err != nil {
			return err
		}
	}

	if descriptor.Validate != nil {
		return descriptor.Validate(cfg)
	}

	return nil
}

// validateField checks one field's value against its descriptor.
func validateField(fieldDescriptor FieldDescriptor, value string, authType Type) error {
	if strings.TrimSpace(value) == "" {
		if fieldDescriptor.Required {
			return fmt.Errorf("authentication property %s is required for type %s",
				fieldDescriptor.Name, authType)
		}
		return nil
	}

	if len(fieldDescriptor.Enum) > 0 && !containsString(fieldDescriptor.Enum, value) {
		return fmt.Errorf("authentication property %s must be one of %s, got: %s",
			fieldDescriptor.Name, strings.Join(fieldDescriptor.Enum, ", "), value)
	}

	if fieldDescriptor.Regex != "" {
		matched, err := regexp.MatchString(fieldDescriptor.Regex, value)
		if err != nil {
			return fmt.Errorf("failed to validate authentication property %s: %w",
				fieldDescriptor.Name, err)
		}
		if !matched {
			return fmt.Errorf("authentication property %s has an invalid format", fieldDescriptor.Name)
		}
	}

	return nil
}

// containsType reports whether types contains authType.
func containsType(types []Type, authType Type) bool {
	for _, candidate := range types {
		if candidate == authType {
			return true
		}
	}
	return false
}

// containsString reports whether values contains value.
func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
