package iampd2j

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

type Converter struct {
	Out io.Writer
	Err io.Writer
}

func NewConverter() *Converter {
	return &Converter{Out: os.Stdout, Err: os.Stderr}
}

func (c *Converter) Convert(src []byte, filename string) error {
	if c.Out == nil {
		c.Out = os.Stdout
	}
	if c.Err == nil {
		c.Err = io.Discard
	}

	f, diags := hclwrite.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return errors.Join(diags.Errs()...)
	}

	var out strings.Builder
	first := true
	for _, block := range f.Body().Blocks() {
		if block.Type() != "data" {
			continue
		}
		labels := block.Labels()
		if len(labels) != 2 || labels[0] != "aws_iam_policy_document" {
			continue
		}
		name := labels[1]
		if !first {
			out.WriteString("\n")
		}
		first = false
		fmt.Fprintf(&out, "# %s\n", name)
		s, err := c.convertPolicy(block.Body())
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		out.WriteString(s)
		out.WriteString("\n")
	}

	if first {
		return errors.New("no aws_iam_policy_document blocks found")
	}

	formatted := hclwrite.Format([]byte(out.String()))
	_, err := c.Out.Write(formatted)
	return err
}

func (c *Converter) convertPolicy(body *hclwrite.Body) (string, error) {
	for _, unsupported := range []string{"source_policy_documents", "override_policy_documents"} {
		if body.GetAttribute(unsupported) != nil {
			fmt.Fprintf(c.Err, "warning: %s is not converted; merge manually\n", unsupported)
		}
	}

	var sb strings.Builder
	sb.WriteString("jsonencode({\n")

	if attr := body.GetAttribute("version"); attr != nil {
		fmt.Fprintf(&sb, "Version = %s\n", exprString(attr.Expr()))
	} else {
		sb.WriteString("Version = \"2012-10-17\"\n")
	}

	if attr := body.GetAttribute("policy_id"); attr != nil {
		fmt.Fprintf(&sb, "Id = %s\n", exprString(attr.Expr()))
	}

	var stmts []string
	for _, b := range body.Blocks() {
		if b.Type() != "statement" {
			continue
		}
		s, err := convertStatement(b.Body())
		if err != nil {
			return "", err
		}
		stmts = append(stmts, s)
	}

	if len(stmts) > 0 {
		sb.WriteString("Statement = [\n")
		for i, s := range stmts {
			sb.WriteString(s)
			if i < len(stmts)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\n")
		}
		sb.WriteString("]\n")
	}

	sb.WriteString("})")
	return sb.String(), nil
}

func convertStatement(body *hclwrite.Body) (string, error) {
	var sb strings.Builder
	sb.WriteString("{\n")

	if attr := body.GetAttribute("sid"); attr != nil {
		fmt.Fprintf(&sb, "Sid = %s\n", exprString(attr.Expr()))
	}

	if attr := body.GetAttribute("effect"); attr != nil {
		fmt.Fprintf(&sb, "Effect = %s\n", exprString(attr.Expr()))
	} else {
		sb.WriteString("Effect = \"Allow\"\n")
	}

	for _, m := range []struct{ hcl, json string }{
		{"actions", "Action"},
		{"not_actions", "NotAction"},
		{"resources", "Resource"},
		{"not_resources", "NotResource"},
	} {
		if attr := body.GetAttribute(m.hcl); attr != nil {
			fmt.Fprintf(&sb, "%s = %s\n", m.json, exprString(attr.Expr()))
		}
	}

	if p, err := buildPrincipals(body, "principals"); err != nil {
		return "", err
	} else if p != "" {
		fmt.Fprintf(&sb, "Principal = %s\n", p)
	}
	if p, err := buildPrincipals(body, "not_principals"); err != nil {
		return "", err
	} else if p != "" {
		fmt.Fprintf(&sb, "NotPrincipal = %s\n", p)
	}

	if cond, err := buildConditions(body); err != nil {
		return "", err
	} else if cond != "" {
		fmt.Fprintf(&sb, "Condition = %s\n", cond)
	}

	sb.WriteString("}")
	return sb.String(), nil
}

func buildPrincipals(body *hclwrite.Body, blockType string) (string, error) {
	type entry struct {
		typeStr string
		idsExpr string
	}
	var entries []entry
	for _, b := range body.Blocks() {
		if b.Type() != blockType {
			continue
		}
		typeAttr := b.Body().GetAttribute("type")
		idsAttr := b.Body().GetAttribute("identifiers")
		if typeAttr == nil || idsAttr == nil {
			return "", fmt.Errorf("%s block requires both type and identifiers", blockType)
		}
		typeStr, ok := unquoteString(exprString(typeAttr.Expr()))
		if !ok {
			return "", fmt.Errorf("%s.type must be a string literal", blockType)
		}
		entries = append(entries, entry{typeStr, exprString(idsAttr.Expr())})
	}
	if len(entries) == 0 {
		return "", nil
	}

	var order []string
	groups := map[string][]string{}
	for _, e := range entries {
		if _, ok := groups[e.typeStr]; !ok {
			order = append(order, e.typeStr)
		}
		groups[e.typeStr] = append(groups[e.typeStr], e.idsExpr)
	}

	var sb strings.Builder
	sb.WriteString("{\n")
	for _, t := range order {
		ids := groups[t]
		var val string
		if len(ids) == 1 {
			val = ids[0]
		} else {
			merged, ok := mergeTupleLiterals(ids)
			if !ok {
				return "", fmt.Errorf("%s.identifiers must be list literals to merge multiple %s blocks with type %q", blockType, blockType, t)
			}
			val = merged
		}
		fmt.Fprintf(&sb, "%s = %s\n", hclKey(t), val)
	}
	sb.WriteString("}")
	return sb.String(), nil
}

// mergeTupleLiterals merges multiple list-literal expressions into a single
// list literal. Returns ok=false if any input is not a tuple literal.
func mergeTupleLiterals(exprs []string) (string, bool) {
	var items []string
	for _, e := range exprs {
		inner, ok := tupleInner(e)
		if !ok {
			return "", false
		}
		if inner != "" {
			items = append(items, inner)
		}
	}
	return "[" + strings.Join(items, ", ") + "]", true
}

func tupleInner(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return "", false
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	inner = strings.TrimSuffix(inner, ",")
	return strings.TrimSpace(inner), true
}

func buildConditions(body *hclwrite.Body) (string, error) {
	type entry struct {
		testStr, varStr, valuesExpr string
	}
	var entries []entry
	for _, b := range body.Blocks() {
		if b.Type() != "condition" {
			continue
		}
		testAttr := b.Body().GetAttribute("test")
		varAttr := b.Body().GetAttribute("variable")
		valuesAttr := b.Body().GetAttribute("values")
		if testAttr == nil || varAttr == nil || valuesAttr == nil {
			return "", fmt.Errorf("condition block requires test, variable, and values")
		}
		testStr, ok1 := unquoteString(exprString(testAttr.Expr()))
		varStr, ok2 := unquoteString(exprString(varAttr.Expr()))
		if !ok1 || !ok2 {
			return "", fmt.Errorf("condition.test and condition.variable must be string literals")
		}
		entries = append(entries, entry{testStr, varStr, exprString(valuesAttr.Expr())})
	}
	if len(entries) == 0 {
		return "", nil
	}

	var testOrder []string
	type varEntry struct{ name, valuesExpr string }
	groups := map[string][]varEntry{}
	for _, e := range entries {
		if _, ok := groups[e.testStr]; !ok {
			testOrder = append(testOrder, e.testStr)
		}
		groups[e.testStr] = append(groups[e.testStr], varEntry{e.varStr, e.valuesExpr})
	}

	var sb strings.Builder
	sb.WriteString("{\n")
	for _, t := range testOrder {
		fmt.Fprintf(&sb, "%s = {\n", hclKey(t))
		for _, ve := range groups[t] {
			fmt.Fprintf(&sb, "%s = %s\n", hclKey(ve.name), ve.valuesExpr)
		}
		sb.WriteString("}\n")
	}
	sb.WriteString("}")
	return sb.String(), nil
}

func exprString(expr *hclwrite.Expression) string {
	return strings.TrimSpace(string(expr.BuildTokens(nil).Bytes()))
}

func unquoteString(s string) (string, bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", false
	}
	inner := s[1 : len(s)-1]
	if strings.ContainsAny(inner, "\"\\$") {
		return "", false
	}
	return inner, true
}

func hclKey(s string) string {
	if isHCLIdentifier(s) {
		return s
	}
	return fmt.Sprintf("%q", s)
}

func isHCLIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !(unicode.IsLetter(r) || r == '_') {
				return false
			}
			continue
		}
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
