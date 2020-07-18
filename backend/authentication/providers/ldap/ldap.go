package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/backend/authentication/jwt"
)

// Type represents the type of the basic authentication provider
const Type = "ldap"

// Provider represents the allowall internal authentication provider
type Provider struct {
	corev2.ObjectMeta `json:"metadata"`
	BindUsername      string
	BindPassword      string
	StartTLS          bool
	URL               string
	UserBaseDN        string
	UserAttribute     string
	UserClass         string

	GroupBaseDN          string // Base search DB for groupgs
	GroupAttribute       string // The attribute that is the name of the group
	GroupClass           string // Group object class
	GroupUserDNAttribute string // The attribute name the user dn is in for the group
}

var timeout = 2 * time.Second

// Authenticate allow all users to authenticate as god
func (p *Provider) Authenticate(ctx context.Context, username, password string) (*corev2.Claims, error) {
	logger.Debugf("Authenticating: %s", username)
	// Ldap Authenticate the user
	dn, err := p.getDN(username)
	if err != nil {
		return nil, err
	}
	if err := p.validatePassword(dn, password); err != nil {
		return nil, err
	}
	groups, err := p.getGroups(dn)
	if err != nil {
		return nil, err
	}
	return p.claims(username, groups)
}

// Takes a username and returns the dn if valid
func (p *Provider) getDN(username string) (string, error) {
	logger.Debugf("Getting DN for: %s", username)
	// Default timeout is 60 seconds.  That is why adjusting it
	l, err := ldap.DialURL(p.URL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return "", err
	}
	defer l.Close()

	// Reconnect with TLS
	if p.StartTLS {
		if err := l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return "", err
		}
	}
	// First bind with a read only user
	if err = l.Bind(p.BindUsername, p.BindPassword); err != nil {
		return "", err
	}
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		p.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=%s)(%s=%s))", p.UserClass, p.UserAttribute, username),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) != 1 {
		return "", errors.New("User does not exist or too many entries returned")
	}
	userdn := sr.Entries[0].DN

	return userdn, nil
}
func (p *Provider) validatePassword(dn string, password string) error {
	logger.Debugf("Validating password for: %s", dn)
	// Default timeout is 60 seconds.  That is why adjusting it
	l, err := ldap.DialURL(p.URL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return err
	}
	defer l.Close()

	// Reconnect with TLS
	if p.StartTLS {
		if err := l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return err
		}
	}
	// Bind as the user to verify their password
	if err := l.Bind(dn, password); err != nil {
		return err
	}
	return nil
}
func (p *Provider) getGroups(userdn string) ([]string, error) {
	logger.Debugf("Getting groups for: %s", userdn)
	// Default timeout is 60 seconds.  That is why adjusting it
	l, err := ldap.DialURL(p.URL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, err
	}
	defer l.Close()

	// Reconnect with TLS
	if p.StartTLS {
		if err := l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return nil, err
		}
	}

	// First bind with a read only user
	if err = l.Bind(p.BindUsername, p.BindPassword); err != nil {
		return nil, err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		p.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=%s)(%s=%s))", p.GroupClass, p.GroupUserDNAttribute, userdn),
		[]string{p.GroupAttribute},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		logger.Debugf("Group search base dn: %s", searchRequest.BaseDN)
		logger.Debugf("Group search filter: %s", searchRequest.Filter)
		return nil, err
	}
	var groups []string
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue(p.GroupAttribute))
	}
	logger.Debugf("%s is a member of: %s", userdn, groups)
	return groups, nil
}

// Refresh renews the user claims with the provider claims
func (p *Provider) Refresh(ctx context.Context, claims *corev2.Claims) (*corev2.Claims, error) {
	logger.Debugf("Refreshing: %s", claims.Provider.UserID)
	dn, err := p.getDN(claims.Provider.UserID)
	if err != nil {
		return nil, err
	}
	groups, err := p.getGroups(dn)
	if err != nil {
		return nil, err
	}
	return p.claims(claims.Provider.UserID, groups)
}

func (p *Provider) claims(username string, groups []string) (*corev2.Claims, error) {
	user := &corev2.User{
		Username: username,
		Groups:   groups,
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
