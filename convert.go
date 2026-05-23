package iampd2j

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

const policyDocType = "aws_iam_policy_document"

// Converter inlines `data "aws_iam_policy_document" "<name>"` blocks as
// jsonencode({ ... }) expressions wherever `data.aws_iam_policy_document.<name>.json`
// is referenced across the *.tf files in Dir.
type Converter struct {
	Dir     string
	Out     io.Writer
	Err     io.Writer
	Verbose bool

	files    map[string]*hclwrite.File
	policies map[string]*policy
}

// policy holds per-data-source state collected during the first pass.
//
// convertible is false for blocks that use source_policy_documents or
// override_policy_documents — those are emitted to stderr as a warning and
// left in place because we can't fold their merge semantics into a single
// jsonencode expression. convertible == false implies keepBlock == true.
//
// keepBlock is set during reference scanning. The block must stay in the file
// if any surviving reference would otherwise dangle:
//   - a non-`.json` attribute access from anywhere (`.minified_json` etc.),
//   - or any reference from inside another policy doc body (those refs
//     persist via the surviving outer body or via the spliced tokens at
//     the reference sites).
//
// External `.json` references to convertible policies are replaced with the
// jsonencode expression regardless of keepBlock, since the replacement is
// self-contained. References *inside* policy doc bodies are left untouched
// — they either get spliced as-is at the outer's reference sites (for
// removable outers) or persist in the kept outer's body (for kept outers).
type policy struct {
	name        string
	path        string
	block       *hclwrite.Block
	tokens      hclwrite.Tokens // jsonencode({...}) tokens; nil if !convertible
	convertible bool
	keepBlock   bool
	// warnedNonJSON is set the first time we emit the "non-.json access is
	// not supported" warning for this policy. Tracked separately from
	// keepBlock so the warning fires deterministically regardless of which
	// reference site happens to be visited first — keepBlock can be set by
	// a silent inside-policy-doc ref, but the user still needs to know
	// they have an unsupported accessor in their code.
	warnedNonJSON bool
}

// NewConverter returns a Converter that reads *.tf files from dir.
func NewConverter(dir string) *Converter {
	return &Converter{
		Dir:      dir,
		Out:      os.Stdout,
		Err:      os.Stderr,
		files:    map[string]*hclwrite.File{},
		policies: map[string]*policy{},
	}
}

// Run loads, converts, and writes results. When inPlace is true, files are
// rewritten on disk; otherwise the rewritten content for any changed file is
// printed to c.Out preceded by a `### <path> ###` header.
func (c *Converter) Run(inPlace bool) error {
	if c.Out == nil {
		c.Out = os.Stdout
	}
	if c.Err == nil {
		c.Err = os.Stderr
	}
	// Reset per-run state so a Converter instance can be reused safely.
	c.files = map[string]*hclwrite.File{}
	c.policies = map[string]*policy{}

	if err := c.load(); err != nil {
		return err
	}
	if err := c.collectPolicies(); err != nil {
		return err
	}
	c.scanReferences()
	return c.rewriteAll(inPlace)
}

func (c *Converter) load() error {
	info, err := os.Stat(c.Dir)
	if err != nil {
		return fmt.Errorf("stat %s: %w", c.Dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", c.Dir)
	}
	pattern := filepath.Join(c.Dir, "*.tf")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob: %w", err)
	}
	sort.Strings(matches)
	var diags hcl.Diagnostics
	for _, p := range matches {
		src, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		f, d := hclwrite.ParseConfig(src, p, hcl.Pos{Line: 1, Column: 1})
		if d.HasErrors() {
			diags = append(diags, d...)
			continue
		}
		c.files[p] = f
	}
	if diags.HasErrors() {
		return errors.Join(diags.Errs()...)
	}
	return nil
}

func (c *Converter) collectPolicies() error {
	paths := c.sortedPaths()
	for _, p := range paths {
		f := c.files[p]
		for _, block := range f.Body().Blocks() {
			if !isPolicyDocBlock(block) {
				continue
			}
			name := block.Labels()[1]
			if existing, dup := c.policies[name]; dup {
				return fmt.Errorf("duplicate data %s.%s (in %s and %s)", policyDocType, name, existing.path, p)
			}
			pol := &policy{name: name, path: p, block: block, convertible: true}

			for _, unsupported := range []string{"source_policy_documents", "override_policy_documents"} {
				if block.Body().GetAttribute(unsupported) != nil {
					fmt.Fprintf(c.Err, "warning: %s: %s.%s uses %s; merge manually\n", p, policyDocType, name, unsupported)
					pol.convertible = false
					pol.keepBlock = true
				}
			}

			if pol.convertible {
				s, err := convertPolicy(block.Body())
				if err != nil {
					return fmt.Errorf("%s: %s.%s: %w", p, policyDocType, name, err)
				}
				tokens, err := parseExprTokens(s)
				if err != nil {
					return fmt.Errorf("%s: %s.%s: jsonencode result re-parse failed: %w", p, policyDocType, name, err)
				}
				pol.tokens = tokens
			}
			c.policies[name] = pol
		}
	}
	return nil
}

// scanReferences walks every body in every file and decides, for each
// convertible policy, whether its data block must be kept (keepBlock).
//
// The single pass is enough because the rule does not depend on iteration
// order: a convertible policy is kept iff
//   - it is referenced via a non-`.json` attribute from a non-policy-doc body,
//   - or it is referenced (with any attribute) from inside any policy doc
//     body — those refs persist either via the kept outer body or via the
//     tokens that get spliced at the outer's reference sites.
func (c *Converter) scanReferences() {
	for _, path := range c.sortedPaths() {
		c.scanBodyRefs(c.files[path].Body(), false, path)
	}
}

func (c *Converter) scanBodyRefs(body *hclwrite.Body, inPolicyDoc bool, path string) {
	// body.Attributes() returns a map; sort by name so any warning we emit
	// uses a deterministic attribute name when a policy has multiple
	// non-`.json` accessors in the same body.
	attrs := body.Attributes()
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c.scanTokenRefs(attrs[n].Expr().BuildTokens(nil), inPolicyDoc, path)
	}
	for _, blk := range body.Blocks() {
		next := inPolicyDoc || isPolicyDocBlock(blk)
		c.scanBodyRefs(blk.Body(), next, path)
	}
}

func (c *Converter) scanTokenRefs(tokens hclwrite.Tokens, inPolicyDoc bool, path string) {
	i := 0
	for i < len(tokens) {
		name, attr, n, ok := matchPolicyDocRef(tokens, i)
		if !ok {
			i++
			continue
		}
		pol, has := c.policies[name]
		if has && pol.convertible {
			// A non-`.json` accessor is always worth warning about, no
			// matter where the ref appears — the user has an unsupported
			// access in their code that we can't fold into jsonencode.
			if attr != "json" {
				if !pol.warnedNonJSON {
					fmt.Fprintf(c.Err, "warning: %s: data.%s.%s.%s is not supported; leaving %s.%s in place\n",
						path, policyDocType, name, attr, policyDocType, name)
					pol.warnedNonJSON = true
				}
				pol.keepBlock = true
			} else if inPolicyDoc {
				pol.keepBlock = true
			}
		}
		i += n
	}
}

func (c *Converter) rewriteAll(inPlace bool) error {
	for _, p := range c.sortedPaths() {
		f := c.files[p]
		changed := c.rewriteBody(f.Body(), p)

		for _, blk := range f.Body().Blocks() {
			if !isPolicyDocBlock(blk) {
				continue
			}
			name := blk.Labels()[1]
			pol, ok := c.policies[name]
			if !ok || !pol.convertible || pol.keepBlock || pol.path != p {
				continue
			}
			f.Body().RemoveBlock(blk)
			changed = true
			if c.Verbose {
				log.Printf("  - remove data.%s.%s in %s", policyDocType, name, p)
			}
		}

		if !changed {
			continue
		}
		body := trimLeadingBlankLines(hclwrite.Format(f.Bytes()))
		if inPlace {
			info, err := os.Stat(p)
			if err != nil {
				return fmt.Errorf("stat %s: %w", p, err)
			}
			if err := os.WriteFile(p, body, info.Mode().Perm()); err != nil {
				return fmt.Errorf("write %s: %w", p, err)
			}
			if c.Verbose {
				log.Printf("rewrote %s", p)
			}
			continue
		}
		if _, err := fmt.Fprintf(c.Out, "### %s ###\n%s", p, body); err != nil {
			return err
		}
	}
	return nil
}

func (c *Converter) rewriteBody(body *hclwrite.Body, path string) bool {
	changed := false
	type snap struct {
		name   string
		tokens hclwrite.Tokens
	}
	var snaps []snap
	for name, attr := range body.Attributes() {
		snaps = append(snaps, snap{name, attr.Expr().BuildTokens(nil)})
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].name < snaps[j].name })
	for _, s := range snaps {
		repl, ok := c.replaceRefsInTokens(s.tokens, path)
		if !ok {
			continue
		}
		body.SetAttributeRaw(s.name, repl)
		changed = true
	}
	for _, blk := range body.Blocks() {
		if isPolicyDocBlock(blk) {
			continue
		}
		if c.rewriteBody(blk.Body(), path) {
			changed = true
		}
	}
	return changed
}

func (c *Converter) replaceRefsInTokens(in hclwrite.Tokens, path string) (hclwrite.Tokens, bool) {
	out := make(hclwrite.Tokens, 0, len(in))
	changed := false
	i := 0
	for i < len(in) {
		name, attr, n, ok := matchPolicyDocRef(in, i)
		if !ok {
			out = append(out, in[i])
			i++
			continue
		}
		pol, has := c.policies[name]
		if !has || !pol.convertible || attr != "json" {
			out = append(out, in[i:i+n]...)
			i += n
			continue
		}
		repl := cloneTokens(pol.tokens)
		if len(repl) > 0 {
			repl[0].SpacesBefore = in[i].SpacesBefore
		}
		if c.Verbose {
			log.Printf("  - inline data.%s.%s.json in %s", policyDocType, name, path)
		}
		out = append(out, repl...)
		i += n
		changed = true
	}
	return out, changed
}

func (c *Converter) sortedPaths() []string {
	paths := make([]string, 0, len(c.files))
	for p := range c.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// matchPolicyDocRef matches `data . aws_iam_policy_document . NAME . ATTR`
// starting at tokens[i]. It returns the policy name, the trailing attribute
// name, the number of tokens consumed, and whether the match succeeded. A
// preceding dot disqualifies the match so we don't confuse a chained access.
func matchPolicyDocRef(t hclwrite.Tokens, i int) (string, string, int, bool) {
	if i+6 >= len(t) {
		return "", "", 0, false
	}
	if i > 0 && t[i-1].Type == hclsyntax.TokenDot {
		return "", "", 0, false
	}
	if t[i].Type != hclsyntax.TokenIdent || string(t[i].Bytes) != "data" {
		return "", "", 0, false
	}
	if t[i+1].Type != hclsyntax.TokenDot {
		return "", "", 0, false
	}
	if t[i+2].Type != hclsyntax.TokenIdent || string(t[i+2].Bytes) != policyDocType {
		return "", "", 0, false
	}
	if t[i+3].Type != hclsyntax.TokenDot {
		return "", "", 0, false
	}
	if t[i+4].Type != hclsyntax.TokenIdent {
		return "", "", 0, false
	}
	if t[i+5].Type != hclsyntax.TokenDot {
		return "", "", 0, false
	}
	if t[i+6].Type != hclsyntax.TokenIdent {
		return "", "", 0, false
	}
	return string(t[i+4].Bytes), string(t[i+6].Bytes), 7, true
}

func isPolicyDocBlock(blk *hclwrite.Block) bool {
	if blk.Type() != "data" {
		return false
	}
	labels := blk.Labels()
	return len(labels) == 2 && labels[0] == policyDocType
}

// parseExprTokens re-parses an HCL expression string into hclwrite tokens by
// embedding it as the RHS of a synthetic attribute and reading the result back.
// This lets us splice convertPolicy's string output into other expressions.
func parseExprTokens(s string) (hclwrite.Tokens, error) {
	src := []byte("__expr = " + s + "\n")
	f, diags := hclwrite.ParseConfig(src, "synthetic", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, errors.Join(diags.Errs()...)
	}
	attr := f.Body().GetAttribute("__expr")
	if attr == nil {
		return nil, errors.New("synthetic __expr attribute missing")
	}
	return attr.Expr().BuildTokens(nil), nil
}

// trimLeadingBlankLines removes any blank lines that hclwrite.Format leaves
// behind when we remove a block from the top of a file.
func trimLeadingBlankLines(b []byte) []byte {
	for len(b) > 0 && b[0] == '\n' {
		b = b[1:]
	}
	return b
}

func cloneTokens(in hclwrite.Tokens) hclwrite.Tokens {
	out := make(hclwrite.Tokens, len(in))
	for i, t := range in {
		nt := *t
		nt.Bytes = append([]byte(nil), t.Bytes...)
		out[i] = &nt
	}
	return out
}

func convertPolicy(body *hclwrite.Body) (string, error) {
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

	sb.WriteString("Statement = [\n")
	for i, s := range stmts {
		sb.WriteString(s)
		if i < len(stmts)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("]\n")

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
		groupKey string // canonical key for grouping/merging (decoded literal or raw source)
		emitKey  string // HCL-formatted key for output (bare/quoted ident or parenthesized expr)
		idsExpr  string
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
		groupKey, emitKey := objectKey(typeAttr.Expr())
		entries = append(entries, entry{groupKey, emitKey, exprString(idsAttr.Expr())})
	}
	if len(entries) == 0 {
		return "", nil
	}

	var order []string
	emitKeys := map[string]string{}
	groups := map[string][]string{}
	for _, e := range entries {
		if _, ok := groups[e.groupKey]; !ok {
			order = append(order, e.groupKey)
			emitKeys[e.groupKey] = e.emitKey
		}
		groups[e.groupKey] = append(groups[e.groupKey], e.idsExpr)
	}

	var sb strings.Builder
	sb.WriteString("{\n")
	for _, k := range order {
		ids := groups[k]
		var val string
		if len(ids) == 1 {
			val = ids[0]
		} else {
			merged, ok := mergeTupleLiterals(ids)
			if !ok {
				return "", fmt.Errorf("%s.identifiers must be list literals to merge multiple %s blocks with the same type", blockType, blockType)
			}
			val = merged
		}
		fmt.Fprintf(&sb, "%s = %s\n", emitKeys[k], val)
	}
	sb.WriteString("}")
	return sb.String(), nil
}

// objectKey turns an attribute expression (typically a `type`, `test`, or
// `variable`) into a pair of strings: a canonical group key used for merging
// duplicates, and an HCL-formatted key suitable for embedding into an object
// constructor. Static string literals become bare/quoted identifiers; any
// other expression is wrapped in parentheses so the output is still valid HCL
// thanks to dynamic-key syntax. Non-literal keys group by source text only.
func objectKey(expr *hclwrite.Expression) (groupKey, emitKey string) {
	raw := exprString(expr)
	if s, ok := unquoteString(raw); ok {
		return s, hclKey(s)
	}
	return raw, "(" + raw + ")"
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

// tupleInner returns the inner text of an HCL tuple constructor expression
// (e.g. `["a", "b"]` → `"a", "b"`). It re-parses the expression to make sure
// the outer brackets really belong to a tuple constructor, so that splice-by-
// string never accepts other bracketed forms such as for-expressions
// (`[for x in xs : x]`) which would produce invalid HCL when merged.
func tupleInner(s string) (string, bool) {
	s = strings.TrimSpace(s)
	expr, diags := hclsyntax.ParseExpression([]byte(s), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return "", false
	}
	if _, ok := expr.(*hclsyntax.TupleConsExpr); !ok {
		return "", false
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	inner = strings.TrimSuffix(inner, ",")
	return strings.TrimSpace(inner), true
}

func buildConditions(body *hclwrite.Body) (string, error) {
	type entry struct {
		testGroup, testEmit string
		varGroup, varEmit   string
		valuesExpr          string
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
		tg, te := objectKey(testAttr.Expr())
		vg, ve := objectKey(varAttr.Expr())
		entries = append(entries, entry{tg, te, vg, ve, exprString(valuesAttr.Expr())})
	}
	if len(entries) == 0 {
		return "", nil
	}

	type varGroup struct {
		order  []string
		emit   map[string]string
		values map[string][]string
	}
	var testOrder []string
	testEmit := map[string]string{}
	testGroups := map[string]*varGroup{}
	for _, e := range entries {
		vg, ok := testGroups[e.testGroup]
		if !ok {
			testOrder = append(testOrder, e.testGroup)
			testEmit[e.testGroup] = e.testEmit
			vg = &varGroup{emit: map[string]string{}, values: map[string][]string{}}
			testGroups[e.testGroup] = vg
		}
		if _, ok := vg.values[e.varGroup]; !ok {
			vg.order = append(vg.order, e.varGroup)
			vg.emit[e.varGroup] = e.varEmit
		}
		vg.values[e.varGroup] = append(vg.values[e.varGroup], e.valuesExpr)
	}

	var sb strings.Builder
	sb.WriteString("{\n")
	for _, t := range testOrder {
		fmt.Fprintf(&sb, "%s = {\n", testEmit[t])
		vg := testGroups[t]
		for _, v := range vg.order {
			vals := vg.values[v]
			var val string
			if len(vals) == 1 {
				val = vals[0]
			} else {
				merged, ok := mergeTupleLiterals(vals)
				if !ok {
					return "", fmt.Errorf("condition.values must be list literals to merge multiple condition blocks with the same test and variable")
				}
				val = merged
			}
			fmt.Fprintf(&sb, "%s = %s\n", vg.emit[v], val)
		}
		sb.WriteString("}\n")
	}
	sb.WriteString("}")
	return sb.String(), nil
}

func exprString(expr *hclwrite.Expression) string {
	return strings.TrimSpace(string(expr.BuildTokens(nil).Bytes()))
}

// unquoteString returns the decoded value of an HCL string literal expression.
// It only accepts templates without any interpolation, so escape sequences and
// stray `$` characters in valid literals are handled correctly while references
// and templates with `${...}` are still rejected.
func unquoteString(s string) (string, bool) {
	expr, diags := hclsyntax.ParseExpression([]byte(s), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return "", false
	}
	tmpl, ok := expr.(*hclsyntax.TemplateExpr)
	if !ok || !tmpl.IsStringLiteral() {
		return "", false
	}
	val, _ := tmpl.Value(nil)
	return val.AsString(), true
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
			if !unicode.IsLetter(r) && r != '_' {
				return false
			}
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
