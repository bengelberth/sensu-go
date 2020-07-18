package allowall

import (
	"context"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/backend/authentication/jwt"
)

// Type represents the type of the basic authentication provider
const Type = "allowall"

// Provider represents the allowall internal authentication provider
type Provider struct {
	corev2.ObjectMeta `json:"metadata"`
}

// Authenticate allow all users to authenticate as god
func (p *Provider) Authenticate(ctx context.Context, username, password string) (*corev2.Claims, error) {
	logger.Debugf("Authenticating: %s", username)
	return p.claims(username)
}

// Refresh renews the user claims with the provider claims
func (p *Provider) Refresh(ctx context.Context, claims *corev2.Claims) (*corev2.Claims, error) {
	logger.Debugf("Refreshing: %s", claims.Provider.UserID)
	return p.claims(claims.Provider.UserID)
}

func (p *Provider) claims(username string) (*corev2.Claims, error) {
	user := &corev2.User{
		Username: username,
		Groups:   []string{"cluster-admins"},
		Disabled: false,
	}
	claims, err := jwt.NewClaims(user)
	claims.Provider = corev2.AuthProviderClaims{
		ProviderID: p.Name(),
		UserID:     username,
	}
	return claims, err
}

// Name returns the provider name
func (p *Provider) Name() string {
	return Type
}

// Type returns the provider type
func (p *Provider) Type() string {
	return Type
}

// GetObjectMeta returns the object metadata for the resource.
func (p *Provider) GetObjectMeta() corev2.ObjectMeta {
	return p.ObjectMeta
}

// SetObjectMeta sets the object metadata for the resource.
func (p *Provider) SetObjectMeta(meta corev2.ObjectMeta) {
	p.ObjectMeta = meta
}

// SetNamespace sets the namespace of the resource.
func (p *Provider) SetNamespace(namespace string) {
	p.Namespace = namespace
}

// StorePrefix gives the path prefix to this resource in the store
func (p *Provider) StorePrefix() string {
	return ""
}

// RBACName describes the name of the resource for RBAC purposes.
func (p *Provider) RBACName() string {
	return ""
}

// URIPath gives the path to the resource, e.g. /checks/checkname
func (p *Provider) URIPath() string {
	return ""
}

// Validate checks if the fields in the resource are valid.
func (p *Provider) Validate() error {
	p.ObjectMeta.Name = Type
	return nil
}
