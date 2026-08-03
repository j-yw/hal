package sandboxruntime

type authenticatedWorkerPrincipalSeal struct{}

type AuthenticatedWorkerPrincipalAuthority struct {
	id         string
	generation string
	seal       *authenticatedWorkerPrincipalSeal
}

type authenticatedWorkerPrincipal struct {
	id                  string
	uid                 uint32
	gid                 uint32
	authority           *AuthenticatedWorkerPrincipalAuthority
	authorityID         string
	authorityGeneration string
	seal                *authenticatedWorkerPrincipalSeal
	self                *authenticatedWorkerPrincipal
}

func NewAuthenticatedWorkerPrincipalAuthority(id, generation string) (*AuthenticatedWorkerPrincipalAuthority, error) {
	if !validJobCredentialSafeID(id) || !validJobCredentialSafeID(generation) {
		return nil, ErrAuthenticatedWorkerPrincipal
	}
	return &AuthenticatedWorkerPrincipalAuthority{
		id:         id,
		generation: generation,
		seal:       &authenticatedWorkerPrincipalSeal{},
	}, nil
}

func (authority *AuthenticatedWorkerPrincipalAuthority) IssueAuthenticatedWorkerPrincipal(id string, uid, gid uint32) (AuthenticatedWorkerPrincipal, error) {
	if authority == nil || authority.seal == nil || !validJobCredentialSafeID(authority.id) || !validJobCredentialSafeID(authority.generation) || !validJobCredentialSafeID(id) {
		return nil, ErrAuthenticatedWorkerPrincipal
	}
	principal := &authenticatedWorkerPrincipal{
		id:                  id,
		uid:                 uid,
		gid:                 gid,
		authority:           authority,
		authorityID:         authority.id,
		authorityGeneration: authority.generation,
		seal:                authority.seal,
	}
	principal.self = principal
	return principal, nil
}

func (authority *AuthenticatedWorkerPrincipalAuthority) ValidateAuthenticatedWorkerPrincipal(principal AuthenticatedWorkerPrincipal) error {
	if authority == nil || authority.seal == nil || principal == nil {
		return ErrAuthenticatedWorkerPrincipal
	}
	issued, ok := principal.(*authenticatedWorkerPrincipal)
	if !ok || issued == nil || issued.self != issued || issued.authority != authority || issued.seal != authority.seal ||
		issued.id == "" || issued.authorityID != authority.id || issued.authorityGeneration != authority.generation {
		return ErrAuthenticatedWorkerPrincipal
	}
	return nil
}

func (*authenticatedWorkerPrincipal) IsAuthenticatedWorkerPrincipal() {}

func (principal *authenticatedWorkerPrincipal) ID() string {
	if principal == nil {
		return ""
	}
	return principal.id
}

func (principal *authenticatedWorkerPrincipal) UID() uint32 {
	if principal == nil {
		return 0
	}
	return principal.uid
}

func (principal *authenticatedWorkerPrincipal) GID() uint32 {
	if principal == nil {
		return 0
	}
	return principal.gid
}

func (principal *authenticatedWorkerPrincipal) AuthorityID() string {
	if principal == nil {
		return ""
	}
	return principal.authorityID
}

func (principal *authenticatedWorkerPrincipal) AuthorityGeneration() string {
	if principal == nil {
		return ""
	}
	return principal.authorityGeneration
}
