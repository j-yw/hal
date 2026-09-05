package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

const sandboxDryRunResolutionUnresolved = "unresolved"

type sandboxDryRunPreview struct {
	Purpose                string                       `json:"purpose"`
	ResourcesCreated       bool                         `json:"resourcesCreated"`
	Target                 sandboxDryRunTargetIntent    `json:"target"`
	Workspace              sandboxDryRunWorkspaceIntent `json:"workspace"`
	Security               sandboxDryRunSecurityIntent  `json:"security"`
	Template               *sandboxDryRunTemplateIntent `json:"template,omitempty"`
	PostExecution          sandboxDryRunPostExecution   `json:"postExecution"`
	UnresolvedRequirements []string                     `json:"unresolvedRequirements"`
	autoEntryMode          string
}

type sandboxDryRunTemplateIntent struct {
	SourceKind string `json:"sourceKind"`
	TrustMode  string `json:"trustMode"`
	Requested  bool   `json:"requested"`
	Resolved   bool   `json:"resolved"`
	Active     bool   `json:"active"`
}

type sandboxDryRunTargetIntent struct {
	Selection   string `json:"selection"`
	SandboxName string `json:"sandboxName,omitempty"`
	HostID      string `json:"hostId,omitempty"`
	Runtime     string `json:"runtime,omitempty"`
	Resolution  string `json:"resolution"`
}

type sandboxDryRunWorkspaceIntent struct {
	Mode       string `json:"mode"`
	Base       string `json:"base,omitempty"`
	Resolution string `json:"resolution"`
}

type sandboxDryRunSecurityIntent struct {
	NetworkPolicy       string   `json:"networkPolicy"`
	NetworkPolicyPreset string   `json:"networkPolicyPreset,omitempty"`
	NetworkRuleCount    int      `json:"networkRuleCount"`
	RequestedModes      []string `json:"requestedSecretModes,omitempty"`
	Enforcement         string   `json:"enforcement"`
	Active              bool     `json:"active"`
}

type sandboxDryRunPostExecution struct {
	SyncOutRequested bool   `json:"syncOutRequested"`
	ApplyRequested   bool   `json:"applyRequested"`
	Resolution       string `json:"resolution"`
}

func newSandboxDryRunPreview(
	purpose string,
	sandboxName string,
	hostID string,
	runtimeDriver string,
	baseBranch string,
	syncOut sandboxSyncOutOptions,
	security sandbox.SecurityEvaluationRequest,
	templateSelection sandboxTemplateSelectionResult,
	autoEntryMode string,
) sandboxDryRunPreview {
	sandboxName = sanitizeSandboxDryRunIntentValue(sandboxName)
	hostID = sanitizeSandboxDryRunIntentValue(hostID)
	runtimeDriver = strings.TrimSpace(runtimeDriver)
	baseBranch = sanitizeSandboxDryRunIntentValue(baseBranch)

	selection := "automatic"
	if sandboxName != "" || hostID != "" || runtimeDriver != "" {
		selection = "constrained"
	}
	securityIntent := sandboxDryRunSecurityIntent{
		NetworkPolicy:  strings.TrimSpace(security.RequestedNetworkPolicy),
		RequestedModes: sanitizeCommandSandboxSecretModes(security.RequestedSecretModes),
		Enforcement:    sandboxDryRunResolutionUnresolved,
		Active:         false,
	}
	if securityIntent.NetworkPolicy == "" {
		securityIntent.NetworkPolicy = sandboxDryRunResolutionUnresolved
	}
	if security.RequestedNetworkPolicyIntent != nil {
		securityIntent.NetworkPolicyPreset = string(security.RequestedNetworkPolicyIntent.Preset)
		securityIntent.NetworkRuleCount = len(security.RequestedNetworkPolicyIntent.Rules)
	}

	preview := sandboxDryRunPreview{
		Purpose:          purpose,
		ResourcesCreated: false,
		Target: sandboxDryRunTargetIntent{
			Selection:   selection,
			SandboxName: sandboxName,
			HostID:      hostID,
			Runtime:     runtimeDriver,
			Resolution:  sandboxDryRunResolutionUnresolved,
		},
		Workspace: sandboxDryRunWorkspaceIntent{
			Mode:       sandbox.SandboxWorkspaceModeClone,
			Base:       baseBranch,
			Resolution: sandboxDryRunResolutionUnresolved,
		},
		Security: securityIntent,
		PostExecution: sandboxDryRunPostExecution{
			SyncOutRequested: syncOut.Enabled,
			ApplyRequested:   syncOut.Apply,
			Resolution:       "not_run",
		},
		UnresolvedRequirements: []string{
			"target_resolution",
			"runtime_capability",
			"workspace_source",
			"security_enforcement",
		},
		autoEntryMode: autoEntryMode,
	}
	if templateSelection.Requested {
		preview.Template = &sandboxDryRunTemplateIntent{
			SourceKind: "oci_artifact",
			TrustMode:  string(templateSelection.TrustMode),
			Requested:  true,
			Resolved:   templateSelection.Resolved,
			Active:     templateSelection.Active,
		}
		preview.UnresolvedRequirements = append(preview.UnresolvedRequirements, "template_acquisition")
	}
	return preview
}

func renderSandboxDryRunPreview(out io.Writer, jsonMode bool, preview sandboxDryRunPreview) error {
	if jsonMode {
		payload, err := marshalSandboxDryRunPreview(preview)
		if err != nil {
			return fmt.Errorf("marshal sandbox dry-run preview: %w", err)
		}
		if _, err := fmt.Fprintln(out, string(payload)); err != nil {
			return fmt.Errorf("write sandbox dry-run preview: %w", err)
		}
		return nil
	}

	targetName := preview.Target.SandboxName
	if targetName == "" {
		targetName = "automatic"
	}
	hostID := preview.Target.HostID
	if hostID == "" {
		hostID = "automatic"
	}
	runtimeDriver := preview.Target.Runtime
	if runtimeDriver == "" {
		runtimeDriver = "automatic"
	}
	baseBranch := preview.Workspace.Base
	if baseBranch == "" {
		baseBranch = "automatic"
	}
	preset := preview.Security.NetworkPolicyPreset
	if preset == "" {
		preset = "default"
	}
	requestedModes := strings.Join(preview.Security.RequestedModes, ",")
	if requestedModes == "" {
		requestedModes = "none"
	}

	if _, err := fmt.Fprintln(out, "Sandbox dry-run preview (no resources created)"); err != nil {
		return fmt.Errorf("write sandbox dry-run preview: %w", err)
	}
	if _, err := fmt.Fprintf(out,
		"Target intent: selection=%s, name=%s, host=%s, runtime=%s, resolution=%s\n",
		preview.Target.Selection,
		targetName,
		hostID,
		runtimeDriver,
		preview.Target.Resolution,
	); err != nil {
		return fmt.Errorf("write sandbox dry-run preview: %w", err)
	}
	if _, err := fmt.Fprintf(out,
		"Workspace intent: mode=%s, base=%s, resolution=%s\n",
		preview.Workspace.Mode,
		baseBranch,
		preview.Workspace.Resolution,
	); err != nil {
		return fmt.Errorf("write sandbox dry-run preview: %w", err)
	}
	if _, err := fmt.Fprintf(out,
		"Security intent: networkPolicy=%s, preset=%s, rules=%d, requestedSecretModes=%s, enforcement=%s, active=%t\n",
		preview.Security.NetworkPolicy,
		preset,
		preview.Security.NetworkRuleCount,
		requestedModes,
		preview.Security.Enforcement,
		preview.Security.Active,
	); err != nil {
		return fmt.Errorf("write sandbox dry-run preview: %w", err)
	}
	if preview.Template != nil {
		if _, err := fmt.Fprintf(out,
			"Template intent: sourceKind=%s, trustMode=%s, requested=%t, resolved=%t, active=%t\n",
			preview.Template.SourceKind,
			preview.Template.TrustMode,
			preview.Template.Requested,
			preview.Template.Resolved,
			preview.Template.Active,
		); err != nil {
			return fmt.Errorf("write sandbox dry-run preview: %w", err)
		}
	}
	if _, err := fmt.Fprintf(out,
		"Post-execution intent: syncOut=%t, apply=%t, resolution=%s\n",
		preview.PostExecution.SyncOutRequested,
		preview.PostExecution.ApplyRequested,
		preview.PostExecution.Resolution,
	); err != nil {
		return fmt.Errorf("write sandbox dry-run preview: %w", err)
	}
	if _, err := fmt.Fprintf(out,
		"Unresolved requirements: %s\n",
		strings.Join(preview.UnresolvedRequirements, ", "),
	); err != nil {
		return fmt.Errorf("write sandbox dry-run preview: %w", err)
	}
	if _, err := fmt.Fprintln(out, "Resources created: false"); err != nil {
		return fmt.Errorf("write sandbox dry-run preview: %w", err)
	}
	return nil
}

func sanitizeSandboxDryRunIntentValue(value string) string {
	value = sanitizeRunPublicString(strings.TrimSpace(value))
	return sandboxRedactor(false, nil).Redact(value)
}

func marshalSandboxDryRunPreview(preview sandboxDryRunPreview) ([]byte, error) {
	summary := "Sandbox dry-run preview; no resources were created."
	switch preview.Purpose {
	case sandbox.SandboxLeasePurposeRun:
		return json.MarshalIndent(struct {
			ContractVersion int                  `json:"contractVersion"`
			OK              bool                 `json:"ok"`
			Iterations      int                  `json:"iterations"`
			Complete        bool                 `json:"complete"`
			DryRun          bool                 `json:"dryRun"`
			Summary         string               `json:"summary"`
			SandboxPreview  sandboxDryRunPreview `json:"sandboxPreview"`
		}{
			ContractVersion: 1,
			OK:              true,
			Iterations:      0,
			Complete:        false,
			DryRun:          true,
			Summary:         summary,
			SandboxPreview:  preview,
		}, "", "  ")
	case sandbox.SandboxLeasePurposeAuto:
		entryMode := preview.autoEntryMode
		if entryMode == "" {
			entryMode = string(autoEntryModeReportDiscovery)
		}
		return json.MarshalIndent(struct {
			ContractVersion int                  `json:"contractVersion"`
			OK              bool                 `json:"ok"`
			EntryMode       string               `json:"entryMode"`
			Resumed         bool                 `json:"resumed"`
			Steps           AutoSteps            `json:"steps"`
			DryRun          bool                 `json:"dryRun"`
			Summary         string               `json:"summary"`
			SandboxPreview  sandboxDryRunPreview `json:"sandboxPreview"`
		}{
			ContractVersion: 2,
			OK:              true,
			EntryMode:       entryMode,
			Resumed:         false,
			Steps:           skippedSandboxDryRunAutoSteps(),
			DryRun:          true,
			Summary:         summary,
			SandboxPreview:  preview,
		}, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported sandbox dry-run purpose %q", preview.Purpose)
	}
}

func skippedSandboxDryRunAutoSteps() AutoSteps {
	skipped := func() AutoStep {
		return AutoStep{Status: autoStepStatusSkipped}
	}
	return AutoSteps{
		Analyze:  skipped(),
		Spec:     skipped(),
		Branch:   skipped(),
		Convert:  skipped(),
		Validate: skipped(),
		Run:      skipped(),
		Review:   skipped(),
		CI:       skipped(),
		Report:   skipped(),
		Archive:  skipped(),
	}
}
