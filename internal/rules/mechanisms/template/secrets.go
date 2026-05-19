package template

import (
	"text/template"
	"text/template/parse"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func registerSecretReferences(store SecretStore, tmpl *template.Template) error {
	refs, err := extractSecretReferences(tmpl)
	if err != nil {
		return err
	}

	seen := make(map[SecretReference]struct{}, len(refs))
	for _, ref := range refs {
		if _, ok := seen[ref]; ok {
			continue
		}

		seen[ref] = struct{}{}

		if err := store.RegisterSecret(ref); err != nil {
			return errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"failed registering secret reference '%s/%s'", ref.Source, ref.Selector,
			).CausedBy(err)
		}
	}

	return nil
}

func extractSecretReferences(tmpl *template.Template) ([]SecretReference, error) {
	var refs []SecretReference

	for _, tpl := range tmpl.Templates() {
		if tpl == nil || tpl.Tree == nil {
			continue
		}

		if err := walkNode(tpl.Root, &refs); err != nil {
			return nil, err
		}
	}

	return refs, nil
}

//nolint:cyclop
func walkNode(node parse.Node, refs *[]SecretReference) error {
	if node == nil {
		return nil
	}

	// parse.Node is an interface. Some parse tree fields may hold typed-nil node
	// values, so the concrete node checks below are intentional and not redundant.

	switch typed := node.(type) {
	case *parse.ListNode:
		if typed == nil {
			return nil
		}

		for _, child := range typed.Nodes {
			if err := walkNode(child, refs); err != nil {
				return err
			}
		}

	case *parse.ActionNode:
		if typed == nil {
			return nil
		}

		return walkPipe(typed.Pipe, refs)

	case *parse.IfNode:
		if typed == nil {
			return nil
		}

		return walkBranch(&typed.BranchNode, refs)

	case *parse.RangeNode:
		if typed == nil {
			return nil
		}

		return walkBranch(&typed.BranchNode, refs)

	case *parse.WithNode:
		if typed == nil {
			return nil
		}

		return walkBranch(&typed.BranchNode, refs)

	case *parse.TemplateNode:
		if typed == nil {
			return nil
		}

		return walkPipe(typed.Pipe, refs)
	}

	return nil
}

func walkBranch(branch *parse.BranchNode, refs *[]SecretReference) error {
	if branch == nil {
		return nil
	}

	if err := walkPipe(branch.Pipe, refs); err != nil {
		return err
	}

	if err := walkNode(branch.List, refs); err != nil {
		return err
	}

	return walkNode(branch.ElseList, refs)
}

func walkPipe(pipe *parse.PipeNode, refs *[]SecretReference) error {
	if pipe == nil {
		return nil
	}

	for _, cmd := range pipe.Cmds {
		if err := walkCommand(cmd, refs); err != nil {
			return err
		}
	}

	return nil
}

func walkCommand(cmd *parse.CommandNode, refs *[]SecretReference) error {
	if cmd == nil || len(cmd.Args) == 0 {
		return nil
	}

	if ident, ok := cmd.Args[0].(*parse.IdentifierNode); ok && ident.Ident == "secret" {
		ref, err := secretReferenceFromCommand(cmd)
		if err != nil {
			return err
		}

		*refs = append(*refs, ref)

		return nil
	}

	for _, arg := range cmd.Args {
		if pipe, ok := arg.(*parse.PipeNode); ok {
			if err := walkPipe(pipe, refs); err != nil {
				return err
			}
		}
	}

	return nil
}

func secretReferenceFromCommand(cmd *parse.CommandNode) (SecretReference, error) {
	if len(cmd.Args) != 3 { //nolint:mnd
		return SecretReference{}, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"secret function expects exactly two string literal arguments",
		)
	}

	source, ok := cmd.Args[1].(*parse.StringNode)
	if !ok {
		return SecretReference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function source argument must be a string literal",
		)
	}

	selector, ok := cmd.Args[2].(*parse.StringNode)
	if !ok {
		return SecretReference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function selector argument must be a string literal",
		)
	}

	if len(source.Text) == 0 {
		return SecretReference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function source argument must not be empty",
		)
	}

	if len(selector.Text) == 0 {
		return SecretReference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function selector argument must not be empty",
		)
	}

	return SecretReference{
		Source:   source.Text,
		Selector: selector.Text,
	}, nil
}
