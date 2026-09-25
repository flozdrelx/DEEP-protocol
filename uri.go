// SPDX-License-Identifier: Apache-2.0

package deep

import (
	"fmt"
	"strings"
)

// URI identifies a resource in a DEEP network. Path, Query and Fragment preserve
// their percent-encoded spelling. Fragment is local to the client and MUST NOT
// be included in requests sent to a peer.
type URI struct {
	Authority string
	Node      string
	Network   string
	Path      string
	Query     string
	Fragment  string
}

const MaxURILength = 4096

// ParseURI parses a DEEP URI without applying DNS or network-specific rules.
// Authorities and the scheme are case-insensitive; paths and queries are not.
func ParseURI(raw string) (URI, error) {
	var result URI
	if len(raw) == 0 || len(raw) > MaxURILength {
		return result, fmt.Errorf("DEEP URI must contain 1 to %d ASCII bytes", MaxURILength)
	}
	if err := validateASCII(raw); err != nil {
		return result, err
	}
	if len(raw) < len("deep://") || !strings.EqualFold(raw[:len("deep://")], "deep://") {
		return result, fmt.Errorf("DEEP URI must start with deep://")
	}
	rest := raw[len("deep://"):]
	authorityEnd := strings.IndexAny(rest, "/?#")
	if authorityEnd < 0 {
		authorityEnd = len(rest)
	}
	result.Authority = strings.ToLower(rest[:authorityEnd])
	if err := ValidateAuthority(result.Authority); err != nil {
		return URI{}, err
	}
	parts := strings.Split(result.Authority, ".")
	result.Node, result.Network = parts[0], parts[1]
	rest = rest[authorityEnd:]
	if index := strings.IndexByte(rest, '#'); index >= 0 {
		result.Fragment, rest = rest[index+1:], rest[:index]
		if err := validateComponent(result.Fragment, true); err != nil {
			return URI{}, fmt.Errorf("invalid URI fragment: %w", err)
		}
	}
	if index := strings.IndexByte(rest, '?'); index >= 0 {
		result.Query, rest = rest[index+1:], rest[:index]
	}
	result.Path = rest
	if result.Path == "" {
		result.Path = "/"
	}
	if err := ValidateResource(result.Path, result.Query); err != nil {
		return URI{}, err
	}
	return result, nil
}

// ValidateAuthority accepts the canonical lowercase node.network form. A label
// is 1..63 ASCII alphanumeric/hyphen characters, with alphanumeric ends.
func ValidateAuthority(authority string) error {
	parts := strings.Split(authority, ".")
	if len(parts) != 2 || !validLabel(parts[0]) || !validLabel(parts[1]) {
		return fmt.Errorf("authority must be canonical lowercase node.network (two ASCII labels)")
	}
	return nil
}

func validLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 || !isLowerAlnum(label[0]) || !isLowerAlnum(label[len(label)-1]) {
		return false
	}
	for index := 0; index < len(label); index++ {
		if !isLowerAlnum(label[index]) && label[index] != '-' {
			return false
		}
	}
	return true
}

func isLowerAlnum(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
}

// ValidateResource checks the exact encoded path and query carried on the wire.
// Percent escapes are validated but never decoded or normalized here.
func ValidateResource(path, query string) error {
	if len(path) == 0 || path[0] != '/' {
		return fmt.Errorf("resource path must start with /")
	}
	resourceLength := len(path)
	if query != "" {
		resourceLength += 1 + len(query)
	}
	if resourceLength > MaxURILength {
		return fmt.Errorf("resource exceeds %d bytes", MaxURILength)
	}
	if err := validateComponent(path, false); err != nil {
		return fmt.Errorf("invalid resource path: %w", err)
	}
	if err := validateComponent(query, true); err != nil {
		return fmt.Errorf("invalid resource query: %w", err)
	}
	return nil
}

func validateASCII(value string) error {
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char <= ' ' || char >= 0x7f || char == '\\' {
			return fmt.Errorf("URI contains a forbidden character at byte %d", index)
		}
	}
	return nil
}

func validateComponent(value string, allowQuestion bool) error {
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char == '%' {
			if index+2 >= len(value) || !isHex(value[index+1]) || !isHex(value[index+2]) {
				return fmt.Errorf("invalid percent escape at byte %d", index)
			}
			index += 2
			continue
		}
		if isLowerAlnum(char) || char >= 'A' && char <= 'Z' || strings.ContainsRune("-._~!$&'()*+,;=:@/", rune(char)) || allowQuestion && char == '?' {
			continue
		}
		return fmt.Errorf("forbidden character at byte %d", index)
	}
	return nil
}

func isHex(char byte) bool {
	return char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F'
}
