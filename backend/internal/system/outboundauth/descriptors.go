// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package outboundauth

// descriptors is the single source of truth for every supported authentication method. Adding a
// method here is all that is needed to make it storable, validatable and console-renderable: no
// other code enumerates methods or field names.
//
// The table is compile-time by design. There is no plugin system in the product, and runtime
// registration would make the supported set depend on initialization order.
var descriptors = []MethodDescriptor{
	{
		Type:        TypeNone,
		DisplayName: "{{t(connections:outboundAuth.method.none)}}",
	},
	{
		Type:        TypeBasic,
		DisplayName: "{{t(connections:outboundAuth.method.basic)}}",
		Fields: []FieldDescriptor{
			{
				Name:        FieldBasicUsername,
				Type:        FieldTypeString,
				Required:    true,
				DisplayName: "{{t(connections:outboundAuth.field.username)}}",
			},
			{
				Name:        FieldBasicPassword,
				Type:        FieldTypeString,
				Required:    true,
				Credential:  true,
				DisplayName: "{{t(connections:outboundAuth.field.password)}}",
			},
		},
	},
}

// Descriptor returns the descriptor for authType.
func Descriptor(authType Type) (MethodDescriptor, bool) {
	for _, descriptor := range descriptors {
		if descriptor.Type == authType {
			return descriptor, true
		}
	}
	return MethodDescriptor{}, false
}

// Descriptors returns the descriptors for the given types, in the order given, skipping any that
// names no known method. Callers pass the set of methods they support and serve the result.
//
// A method that takes no fields carries an empty slice rather than a nil one: this result is
// serialized straight to the API, where the field is declared as an array, and a nil slice would
// reach the client as null.
func Descriptors(types []Type) []MethodDescriptor {
	result := make([]MethodDescriptor, 0, len(types))
	for _, authType := range types {
		if descriptor, ok := Descriptor(authType); ok {
			if descriptor.Fields == nil {
				descriptor.Fields = []FieldDescriptor{}
			}
			result = append(result, descriptor)
		}
	}
	return result
}

// field returns the descriptor of the named field of authType.
func field(authType Type, name string) (FieldDescriptor, bool) {
	descriptor, ok := Descriptor(authType)
	if !ok {
		return FieldDescriptor{}, false
	}
	for _, candidate := range descriptor.Fields {
		if candidate.Name == name {
			return candidate, true
		}
	}
	return FieldDescriptor{}, false
}
