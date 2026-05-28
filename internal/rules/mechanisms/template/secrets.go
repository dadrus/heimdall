package template

import (
	"text/template"
	"text/template/parse"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func toStringSecret(secret secrets.Secret) (string, error) {
	ss, ok := secret.(secrets.StringSecret)
	if !ok {
		return "", secrets.ErrSecretKindMismatch
	}

	return ss.Value(), nil
}

func createSecretInformers(
	resolver secrets.Resolver,
	tmpl *template.Template,
	forbidden bool,
) (map[secrets.Reference]*secrets.SecretInformer[string], error) {
	refs, err := extractSecretReferences(tmpl)
	if err != nil {
		return nil, err
	}

	if len(refs) == 0 {
		return nil, nil //nolint:nilnil
	}

	if forbidden {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret template function is not allowed in this context",
		)
	}

	if len(refs) != 0 && resolver == nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"secret resolver has not been configured in the given context - this is a bug",
		)
	}

	informers := make(map[secrets.Reference]*secrets.SecretInformer[string], len(refs))

	for _, ref := range refs {
		if _, ok := informers[ref]; ok {
			continue
		}

		informer, err := secrets.NewSecretInformer(
			resolver,
			ref,
			secrets.WithConverter(toStringSecret),
		)
		if err != nil {
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"failed registering secret reference '%s/%s'", ref.Source, ref.Selector,
			).CausedBy(err)
		}

		informers[ref] = informer
	}

	return informers, nil
}

func extractSecretReferences(tmpl *template.Template) ([]secrets.Reference, error) {
	var refs []secrets.Reference

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
func walkNode(node parse.Node, refs *[]secrets.Reference) error {
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

func walkBranch(branch *parse.BranchNode, refs *[]secrets.Reference) error {
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

func walkPipe(pipe *parse.PipeNode, refs *[]secrets.Reference) error {
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

func walkCommand(cmd *parse.CommandNode, refs *[]secrets.Reference) error {
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

func secretReferenceFromCommand(cmd *parse.CommandNode) (secrets.Reference, error) {
	if len(cmd.Args) != 3 { //nolint:mnd
		return secrets.Reference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function expects exactly two string literal arguments",
		)
	}

	source, ok := cmd.Args[1].(*parse.StringNode)
	if !ok {
		return secrets.Reference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function source argument must be a string literal",
		)
	}

	selector, ok := cmd.Args[2].(*parse.StringNode)
	if !ok {
		return secrets.Reference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function selector argument must be a string literal",
		)
	}

	if len(source.Text) == 0 {
		return secrets.Reference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function source argument must not be empty",
		)
	}

	if len(selector.Text) == 0 {
		return secrets.Reference{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret function selector argument must not be empty",
		)
	}

	return secrets.Reference{
		Source:   source.Text,
		Selector: selector.Text,
	}, nil
}
