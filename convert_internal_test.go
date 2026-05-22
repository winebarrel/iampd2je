package iampd2j

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTupleInner_ParseError(t *testing.T) {
	_, ok := tupleInner("[unterminated")
	assert.False(t, ok)
}

func TestTupleInner_NotTupleConstructor(t *testing.T) {
	// `[for x in xs : x]` is a *hclsyntax.ForExpr, not *TupleConsExpr.
	_, ok := tupleInner("[for x in xs : x]")
	assert.False(t, ok)
}

func TestUnquoteString_ParseError(t *testing.T) {
	_, ok := unquoteString(`"unterminated`)
	assert.False(t, ok)
}

func TestUnquoteString_NotTemplate(t *testing.T) {
	// A bare reference parses as ScopeTraversalExpr, not TemplateExpr.
	_, ok := unquoteString("var.x")
	assert.False(t, ok)
}

func TestUnquoteString_InterpolatedTemplate(t *testing.T) {
	// A template that contains an interpolation is not IsStringLiteral.
	_, ok := unquoteString(`"hello ${var.x}"`)
	assert.False(t, ok)
}

func TestIsHCLIdentifier_Empty(t *testing.T) {
	assert.False(t, isHCLIdentifier(""))
}

func TestIsHCLIdentifier_LeadingDigit(t *testing.T) {
	assert.False(t, isHCLIdentifier("1foo"))
}

func TestIsHCLIdentifier_InvalidMidChar(t *testing.T) {
	assert.False(t, isHCLIdentifier("foo:bar"))
}

func TestIsHCLIdentifier_Valid(t *testing.T) {
	assert.True(t, isHCLIdentifier("foo_bar-1"))
}
