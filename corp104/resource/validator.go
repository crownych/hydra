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
	nameRegex    = regexp.MustCompile(`^[a-zA-Z0-9]+[a-zA-Z0-9_\-\.]+$`)
	versionRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
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
		return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Name' Error:Name pattern should be "%s"` + nameRegex.String()))
	}

	if !versionRegex.MatchString(r.Version) {
		return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Version' Error:Version pattern should be "%s"` + versionRegex.String()))
	}

	if r.GrantTypes[0] != "urn:ietf:params:oauth:grant-type:token-exchange" {
		return pkg.NewBadRequestError(`Key: 'Resource.GrantTypes' Error:GrantType should be "urn:ietf:params:oauth:grant-type:token-exchange"`)
	}

	resourceScope := fmt.Sprintf("%s.v%s", r.Name, r.Version)
	scopeNamePrefix := resourceScope + ":"
	rootScopeNames := make([]string, len(r.Scopes))
	for _, scope := range r.Scopes {
		if strings.HasPrefix(scope.Name, scopeNamePrefix) {
			return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Scopes.Name' Error:Name should starts with "%s"`, scopeNamePrefix))
		}
		if scope.AuthType != "" && !stringslice.Has([]string{"none", "client", "user", "company"}, scope.AuthType) {
			return pkg.NewBadRequestError(`Key: 'Resource.Scopes.AuthType' Error:AuthType should be 'none', 'client', 'user', 'company' or empty`)
		}
		rootScopeNames = append(rootScopeNames, scope.Name)
	}

	for _, p := range r.Paths {
		for _, m := range p.Methods {
			if hasDuplicates(m.Scopes) {
				return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Paths["%s"].Methods["%s"].Scopes' Error:Duplicate scopes`, p.Name, m.Name))
			}

			for _, ms := range m.Scopes {
				if ms != resourceScope && !stringslice.Has(rootScopeNames, ms) {
					return pkg.NewBadRequestError(fmt.Sprintf(`Key: 'Resource.Paths["%s"].Methods["%s"].Scopes' Error:'%s' is not declared in Resource.Scopes`, p.Name, m.Name, ms))
				}
			}
		}
	}

	return nil
}
