package resource

import (
	"fmt"
	"github.com/go-playground/validator"
	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/hydra/pkg"
	"net/url"
	"regexp"
	"strings"
)

var (
	nameRegex     = regexp.MustCompile(`^[a-zA-Z0-9]+[a-zA-Z0-9_\-\.]+$`)
	pathNameRegex = regexp.MustCompile(`^/|(/[a-zA-Z0-9\-\._~%!\$&'()*+,;=:@]+|\/\{[a-zA-Z_]+[a-zA-Z0-9_]*\})+$`)
	graphQLOperationNameRegex = regexp.MustCompile(`^[a-zA-Z_]+[a-zA-Z0-9_]*(\/[a-zA-Z_]+[a-zA-Z0-9_]*)*$`)
)

type Validator struct {
	validate *validator.Validate
}

func NewValidator() *Validator {
	return &Validator{
		validate: validator.New(),
	}
}

func (v *Validator) Validate(r *Resource) error {
	err := v.validate.Struct(r)
	if err != nil {
		return pkg.NewBadRequestError(err.Error())
	}

	if resourceUrl, err := url.Parse(r.Uri); err != nil {
		return pkg.NewBadRequestError("Key: 'Resource.Uri' Error:Invalid URL")
	} else {
		if resourceUrl.Scheme != "https" {
			return pkg.NewBadRequestError("Key: 'Resource.Uri' Error:Scheme must be https")
		}
		if resourceUrl.Fragment != "" {
			return pkg.NewBadRequestError("Key: 'Resource.Uri' Error:Field 'Uri' must not contain fragments (#)")
		}
	}

	if !nameRegex.MatchString(r.Name) {
		return pkg.NewBadRequestError(`Key: 'Resource.Name' Error:Invalid name`)
	}

	r.Urn = r.GetUrn()
	r.DefaultScope = r.GetDefaultScope()

	scopeNamePrefix := r.DefaultScope + ":"
	var rootScopeNames []string
	for _, scope := range r.Scopes {
		if !strings.HasPrefix(scope.Name, scopeNamePrefix) {
			return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Scopes.Name' Error:Scope name should starts with "%s"`, scopeNamePrefix))
		}

		if scope.ScopeAuthType != "" && !stringslice.Has([]string{"none", "client", "user", "company"}, scope.ScopeAuthType) {
			return pkg.NewBadRequestError(`Key: 'Resource.Scopes.AuthType' Error:ScopeAuthType should be 'none', 'client', 'user', 'company' or empty`)
		}
		rootScopeNames = append(rootScopeNames, scope.Name)
	}
	if hasDuplicates(rootScopeNames) {
		return pkg.NewBadRequestError(`Key: 'Resource.Scopes' Error:Duplicate scopes`)
	}

	switch r.Type {
	case RestResourceType:
		if len(r.Paths) == 0 {
			return pkg.NewBadRequestError(`Key: 'Resource.Paths' Error:Field 'Paths' should not be empty`)
		}
		for idx, p := range r.Paths {
			if !pathNameRegex.MatchString(p.Name) {
				return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Paths[%d].Name' Error:Invalid name`, idx))
			}

			if len(p.Methods) == 0 {
				return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Paths["%s"].Methods' Error:Field 'Methods' should not be empty`, p.Name))
			}

			for _, m := range p.Methods {
				if hasDuplicates(m.Scopes) {
					return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Paths["%s"].Methods["%s"].Scopes' Error:Duplicate scopes`, p.Name, m.Name))
				}

				for _, ms := range m.Scopes {
					if ms != r.DefaultScope && !stringslice.Has(rootScopeNames, ms) {
						return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Paths["%s"].Methods["%s"].Scopes' Error:'%s' is neither the default scope nor declared in Resource.Scopes`, p.Name, m.Name, ms))
					}
				}
			}
		}
	case GraphQLResourceType:
		if len(r.GraphQLOperations) == 0 {
			return pkg.NewBadRequestError(`Key: 'Resource.GraphQLOperations' Error:Field 'GraphQLOperations' should not be empty`)
		}

		var nameTypeList []string
		for idx, p := range r.GraphQLOperations {
			if !graphQLOperationNameRegex.MatchString(p.Name) {
				return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.GraphQLOperations[%d].Name' Error:Invalid name`, idx))
			}
			nameTypeList = append(nameTypeList, p.Name + ":" + p.Type)

			if hasDuplicates(p.Scopes) {
				return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.GraphQLOperations["%s"].Scopes' Error:Duplicate scopes`, p.Name))
			}

			for _, ms := range p.Scopes {
				if ms != r.DefaultScope && !stringslice.Has(rootScopeNames, ms) {
					return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.GraphQLOperations["%s"].Scopes' Error:'%s' is neither the default scope nor declared in Resource.Scopes`, p.Name, ms))
				}

			}
		}
		if hasDuplicates(nameTypeList) {
			return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.GraphQLOperations' Error:Duplicate name & type declaration`))
		}
	}

	return nil
}
