package session

import (
	"sort"
	"sync"
)

type GenerationGate struct {
	mu             sync.Mutex
	bootGeneration string
	hooks          GateHooks
	attempts       int
	nextAttemptID  uint64
	pending        map[uint64]bool
	active         *State
	jobs           map[string]struct{}
	terminal       bool
}

type Attempt struct {
	gate *GenerationGate
	id   uint64
	done bool
}

func NewGenerationGate(bootGeneration string, hooks GateHooks) (*GenerationGate, error) {
	if !validToken(bootGeneration) {
		return nil, ErrMalformedHandshake
	}
	return &GenerationGate{
		bootGeneration: bootGeneration,
		hooks:          hooks,
		pending:        make(map[uint64]bool),
		jobs:           make(map[string]struct{}),
	}, nil
}

func (g *GenerationGate) Begin() (*Attempt, error) {
	if g == nil {
		return nil, ErrInvalidState
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.terminal {
		return nil, ErrReconnectRejected
	}
	if g.active != nil {
		return nil, ErrAlreadyActive
	}
	if g.attempts >= MaxPreAuthConnections {
		return nil, ErrPreAuthExhausted
	}
	g.attempts++
	g.nextAttemptID++
	id := g.nextAttemptID
	g.pending[id] = true
	return &Attempt{gate: g, id: id}, nil
}

func (a *Attempt) Authenticate(state *State) error {
	if a == nil || a.gate == nil || state == nil || !state.Established() {
		return ErrInvalidState
	}
	g := a.gate
	g.mu.Lock()
	if a.done {
		g.mu.Unlock()
		return ErrInvalidState
	}
	if !g.pending[a.id] {
		terminal := g.terminal
		active := g.active != nil
		isActive := g.active == state
		g.mu.Unlock()
		if !isActive {
			state.Revoke()
		}
		if terminal {
			return ErrReconnectRejected
		}
		if active {
			return ErrAlreadyActive
		}
		return ErrInvalidState
	}
	a.done = true
	delete(g.pending, a.id)
	if g.terminal {
		g.mu.Unlock()
		state.Revoke()
		return ErrReconnectRejected
	}
	if g.active != nil {
		g.mu.Unlock()
		state.Revoke()
		return ErrAlreadyActive
	}
	g.active = state
	for id := range g.pending {
		delete(g.pending, id)
	}
	g.mu.Unlock()
	return nil
}

func (a *Attempt) Fail() {
	if a == nil || a.gate == nil {
		return
	}
	g := a.gate
	g.mu.Lock()
	if a.done || !g.pending[a.id] {
		g.mu.Unlock()
		return
	}
	a.done = true
	delete(g.pending, a.id)
	shouldExhaust := g.active == nil && !g.terminal && g.attempts >= MaxPreAuthConnections && len(g.pending) == 0
	if shouldExhaust {
		g.terminal = true
	}
	hook := g.hooks.NotifyLoss
	g.mu.Unlock()
	if shouldExhaust && hook != nil {
		hook(LossEvent{Reason: LossReasonPreAuthExhausted})
	}
}

func (g *GenerationGate) RegisterJobGeneration(jobGeneration string) error {
	if !validJobIdentityToken(jobGeneration) {
		return ErrIdentityMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.terminal {
		return ErrReconnectRejected
	}
	if g.active == nil || !g.active.Established() {
		return ErrInvalidState
	}
	g.jobs[jobGeneration] = struct{}{}
	return nil
}

func (g *GenerationGate) Lose(reason LossReason) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.terminal || g.active == nil {
		g.mu.Unlock()
		return
	}
	g.terminal = true
	active := g.active
	g.active = nil
	jobs := make([]string, 0, len(g.jobs))
	for job := range g.jobs {
		jobs = append(jobs, job)
	}
	sort.Strings(jobs)
	g.jobs = make(map[string]struct{})
	revokeHook := g.hooks.RevokeJob
	lossHook := g.hooks.NotifyLoss
	g.mu.Unlock()

	active.Revoke()
	for _, job := range jobs {
		if revokeHook != nil {
			revokeHook(job)
		}
	}
	if lossHook != nil {
		lossHook(LossEvent{Reason: reason, JobGenerations: append([]string(nil), jobs...)})
	}
}

func (g *GenerationGate) Ready() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.terminal
}

func (g *GenerationGate) Claimed() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active != nil && !g.terminal
}

func (g *GenerationGate) BootGeneration() string {
	if g == nil {
		return ""
	}
	return g.bootGeneration
}
