package iampd2j

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tokensOf(t *testing.T, expr string) hclwrite.Tokens {
	t.Helper()
	src := []byte("x = " + expr + "\n")
	f, diags := hclwrite.ParseConfig(src, "t", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors())
	return f.Body().GetAttribute("x").Expr().BuildTokens(nil)
}

func TestMatchPolicyDocRef_TooShort(t *testing.T) {
	_, _, n, ok := matchPolicyDocRef(tokensOf(t, "data.aws_iam_policy_document.p"), 0)
	assert.False(t, ok)
	assert.Zero(t, n)
}

func TestMatchPolicyDocRef_PrecededByDot(t *testing.T) {
	// `x.data.aws_iam_policy_document.p.json` — the `data` token is preceded
	// by a dot, so the match must fail at index 2.
	toks := tokensOf(t, "x.data.aws_iam_policy_document.p.json")
	_, _, _, ok := matchPolicyDocRef(toks, 2)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_NotDataIdent(t *testing.T) {
	toks := tokensOf(t, "other.aws_iam_policy_document.p.json.extra")
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_WrongType(t *testing.T) {
	toks := tokensOf(t, "data.aws_other.p.json.extra")
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_FirstTokenNotIdent(t *testing.T) {
	// Starts with `(` so token[i] is not an Ident.
	toks := tokensOf(t, "(data.aws_iam_policy_document.p.json)")
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

// rawToken makes a single hclwrite token of the given type with the given text.
func rawToken(tt hclsyntax.TokenType, s string) *hclwrite.Token {
	return &hclwrite.Token{Type: tt, Bytes: []byte(s)}
}

func TestMatchPolicyDocRef_Tok1NotDot(t *testing.T) {
	toks := hclwrite.Tokens{
		rawToken(hclsyntax.TokenIdent, "data"),
		rawToken(hclsyntax.TokenIdent, "x"), // not a dot
		rawToken(hclsyntax.TokenIdent, "aws_iam_policy_document"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "p"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "json"),
	}
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_Tok3NotDot(t *testing.T) {
	toks := hclwrite.Tokens{
		rawToken(hclsyntax.TokenIdent, "data"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "aws_iam_policy_document"),
		rawToken(hclsyntax.TokenIdent, "p"), // not dot
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "x"),
		rawToken(hclsyntax.TokenIdent, "json"),
	}
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_Tok4NotIdent(t *testing.T) {
	toks := hclwrite.Tokens{
		rawToken(hclsyntax.TokenIdent, "data"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "aws_iam_policy_document"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenOBrack, "["), // not ident
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "json"),
	}
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_Tok5NotDot(t *testing.T) {
	toks := hclwrite.Tokens{
		rawToken(hclsyntax.TokenIdent, "data"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "aws_iam_policy_document"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "p"),
		rawToken(hclsyntax.TokenIdent, "json"), // missing dot
		rawToken(hclsyntax.TokenIdent, "x"),
	}
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_Tok6NotIdent(t *testing.T) {
	toks := hclwrite.Tokens{
		rawToken(hclsyntax.TokenIdent, "data"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "aws_iam_policy_document"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "p"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenOBrack, "["), // not ident
	}
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_TrailingDot(t *testing.T) {
	toks := tokensOf(t, "data.aws_iam_policy_document.p.json.something")
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_TrailingBracket(t *testing.T) {
	toks := tokensOf(t, "data.aws_iam_policy_document.p.json[0]")
	_, _, _, ok := matchPolicyDocRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocRef_OK(t *testing.T) {
	toks := tokensOf(t, "data.aws_iam_policy_document.policy_name.json")
	name, attr, n, ok := matchPolicyDocRef(toks, 0)
	assert.True(t, ok)
	assert.Equal(t, "policy_name", name)
	assert.Equal(t, "json", attr)
	assert.Equal(t, 7, n)
}

func TestMatchPolicyDocBareRef_OK(t *testing.T) {
	toks := tokensOf(t, "data.aws_iam_policy_document.policy_name")
	name, n, ok := matchPolicyDocBareRef(toks, 0)
	assert.True(t, ok)
	assert.Equal(t, "policy_name", name)
	assert.Equal(t, 5, n)
}

func TestMatchPolicyDocBareRef_TooShort(t *testing.T) {
	toks := tokensOf(t, "data.aws_iam_policy_document")
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_PrecededByDot(t *testing.T) {
	toks := tokensOf(t, "x.data.aws_iam_policy_document.p")
	_, _, ok := matchPolicyDocBareRef(toks, 2)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_TrailingDot(t *testing.T) {
	// matchPolicyDocRef handles this; matchPolicyDocBareRef must defer.
	toks := tokensOf(t, "data.aws_iam_policy_document.p.json")
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_TrailingBracket(t *testing.T) {
	toks := tokensOf(t, "data.aws_iam_policy_document.p[0]")
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_NotDataIdent(t *testing.T) {
	toks := tokensOf(t, "other.aws_iam_policy_document.p")
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_WrongType(t *testing.T) {
	toks := tokensOf(t, "data.aws_other.p")
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_FirstTokenNotIdent(t *testing.T) {
	toks := tokensOf(t, "(data.aws_iam_policy_document.p)")
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_Tok1NotDot(t *testing.T) {
	toks := hclwrite.Tokens{
		rawToken(hclsyntax.TokenIdent, "data"),
		rawToken(hclsyntax.TokenIdent, "x"),
		rawToken(hclsyntax.TokenIdent, "aws_iam_policy_document"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "p"),
	}
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_Tok3NotDot(t *testing.T) {
	toks := hclwrite.Tokens{
		rawToken(hclsyntax.TokenIdent, "data"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "aws_iam_policy_document"),
		rawToken(hclsyntax.TokenIdent, "x"),
		rawToken(hclsyntax.TokenIdent, "p"),
	}
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestMatchPolicyDocBareRef_Tok4NotIdent(t *testing.T) {
	toks := hclwrite.Tokens{
		rawToken(hclsyntax.TokenIdent, "data"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenIdent, "aws_iam_policy_document"),
		rawToken(hclsyntax.TokenDot, "."),
		rawToken(hclsyntax.TokenOBrack, "["),
	}
	_, _, ok := matchPolicyDocBareRef(toks, 0)
	assert.False(t, ok)
}

func TestParseExprTokens_ParseError(t *testing.T) {
	_, err := parseExprTokens("[unterminated")
	require.Error(t, err)
}

func TestTrimLeadingBlankLines(t *testing.T) {
	assert.Equal(t, []byte("a\n"), trimLeadingBlankLines([]byte("\n\na\n")))
	assert.Equal(t, []byte(""), trimLeadingBlankLines([]byte("")))
}

func TestUnwrapSingletonTuple_Singleton(t *testing.T) {
	assert.Equal(t, `"x"`, unwrapSingletonTuple(`["x"]`))
}

func TestUnwrapSingletonTuple_MultipleElements(t *testing.T) {
	// More than one element → input unchanged.
	assert.Equal(t, `["a", "b"]`, unwrapSingletonTuple(`["a", "b"]`))
}

func TestUnwrapSingletonTuple_Empty(t *testing.T) {
	// Zero elements → input unchanged (no element to promote).
	assert.Equal(t, `[]`, unwrapSingletonTuple(`[]`))
}

func TestUnwrapSingletonTuple_NotATuple(t *testing.T) {
	// Bare reference parses as ScopeTraversalExpr, not TupleConsExpr.
	assert.Equal(t, "var.x", unwrapSingletonTuple("var.x"))
}

func TestUnwrapSingletonTuple_ForExpr(t *testing.T) {
	// `[for ...]` is a ForExpr, not a TupleConsExpr — leave it alone even
	// though it's bracketed.
	in := "[for x in xs : x]"
	assert.Equal(t, in, unwrapSingletonTuple(in))
}

func TestUnwrapSingletonTuple_ParseError(t *testing.T) {
	// Malformed input is left as-is rather than panicking.
	assert.Equal(t, "[unterminated", unwrapSingletonTuple("[unterminated"))
}

func TestUnwrapSingletonTuple_NestedElement(t *testing.T) {
	// The unwrapped element keeps its full source text, including nested
	// expressions and surrounding whitespace inside the brackets.
	assert.Equal(t, "var.x", unwrapSingletonTuple("[ var.x ]"))
}

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
