package sandboxruntime

type authenticatedWorkerPrincipalSeal struct{}

// AuthenticatedWorkerPrincipalAuthority is an owned live handle. All live
// data is behind private owner-checked state, so only the constructor-owned
// handle is operational.
type AuthenticatedWorkerPrincipalAuthority struct {
	identity authenticatedWorkerPrincipalAuthorityOwner
	state    *authenticatedWorkerPrincipalAuthorityState
}

type authenticatedWorkerPrincipalAuthorityOwner struct{ _ byte }

type authenticatedWorkerPrincipalAuthorityState struct {
	owner      *authenticatedWorkerPrincipalAuthorityOwner
	id         string
	generation string
	seal       *authenticatedWorkerPrincipalSeal
}

type authenticatedWorkerPrincipal struct {
	identity authenticatedWorkerPrincipalOwner
	state    *authenticatedWorkerPrincipalState
}

type authenticatedWorkerPrincipalOwner struct{ _ byte }

type authenticatedWorkerPrincipalState struct {
	owner               *authenticatedWorkerPrincipalOwner
	id                  string
	uid                 uint32
	gid                 uint32
	authority           *authenticatedWorkerPrincipalAuthorityState
	authorityID         string
	authorityGeneration string
	seal                *authenticatedWorkerPrincipalSeal
}

func NewAuthenticatedWorkerPrincipalAuthority(id, generation string) (*AuthenticatedWorkerPrincipalAuthority, error) {
	if !validJobCredentialSafeID(id) || !validJobCredentialSafeID(generation) {
		return nil, ErrAuthenticatedWorkerPrincipal
	}
	authority := &AuthenticatedWorkerPrincipalAuthority{}
	authority.state = &authenticatedWorkerPrincipalAuthorityState{
		owner:      &authority.identity,
		id:         id,
		generation: generation,
		seal:       &authenticatedWorkerPrincipalSeal{},
	}
	return authority, nil
}

func (authority *AuthenticatedWorkerPrincipalAuthority) IssueAuthenticatedWorkerPrincipal(id string, uid, gid uint32) (AuthenticatedWorkerPrincipal, error) {
	state, ok := loadAuthenticatedWorkerPrincipalAuthorityState(authority)
	if !ok || !validJobCredentialSafeID(id) {
		return nil, ErrAuthenticatedWorkerPrincipal
	}
	principal := &authenticatedWorkerPrincipal{}
	principal.state = &authenticatedWorkerPrincipalState{
		owner:               &principal.identity,
		id:                  id,
		uid:                 uid,
		gid:                 gid,
		authority:           state,
		authorityID:         state.id,
		authorityGeneration: state.generation,
		seal:                state.seal,
	}
	return principal, nil
}

func (authority *AuthenticatedWorkerPrincipalAuthority) ValidateAuthenticatedWorkerPrincipal(principal AuthenticatedWorkerPrincipal) error {
	authorityState, ok := loadAuthenticatedWorkerPrincipalAuthorityState(authority)
	if !ok || principal == nil {
		return ErrAuthenticatedWorkerPrincipal
	}
	issued, ok := principal.(*authenticatedWorkerPrincipal)
	if !ok || issued == nil {
		return ErrAuthenticatedWorkerPrincipal
	}
	principalState, ok := loadAuthenticatedWorkerPrincipalState(issued)
	if !ok || principalState.authority != authorityState ||
		principalState.seal != authorityState.seal || !validJobCredentialSafeID(principalState.id) ||
		principalState.authorityID != authorityState.id || principalState.authorityGeneration != authorityState.generation {
		return ErrAuthenticatedWorkerPrincipal
	}
	return nil
}

func (*authenticatedWorkerPrincipal) IsAuthenticatedWorkerPrincipal() {}

func (principal *authenticatedWorkerPrincipal) ID() string {
	state, ok := loadAuthenticatedWorkerPrincipalState(principal)
	if !ok {
		return ""
	}
	return state.id
}

func (principal *authenticatedWorkerPrincipal) UID() uint32 {
	state, ok := loadAuthenticatedWorkerPrincipalState(principal)
	if !ok {
		return 0
	}
	return state.uid
}

func (principal *authenticatedWorkerPrincipal) GID() uint32 {
	state, ok := loadAuthenticatedWorkerPrincipalState(principal)
	if !ok {
		return 0
	}
	return state.gid
}

func (principal *authenticatedWorkerPrincipal) AuthorityID() string {
	state, ok := loadAuthenticatedWorkerPrincipalState(principal)
	if !ok {
		return ""
	}
	return state.authorityID
}

func (principal *authenticatedWorkerPrincipal) AuthorityGeneration() string {
	state, ok := loadAuthenticatedWorkerPrincipalState(principal)
	if !ok {
		return ""
	}
	return state.authorityGeneration
}

func loadAuthenticatedWorkerPrincipalAuthorityState(authority *AuthenticatedWorkerPrincipalAuthority) (*authenticatedWorkerPrincipalAuthorityState, bool) {
	if authority == nil || authority.state == nil || authority.state.owner != &authority.identity {
		return nil, false
	}
	return authority.state, true
}

func loadAuthenticatedWorkerPrincipalState(principal *authenticatedWorkerPrincipal) (*authenticatedWorkerPrincipalState, bool) {
	if principal == nil || principal.state == nil || principal.state.owner != &principal.identity {
		return nil, false
	}
	return principal.state, true
}
