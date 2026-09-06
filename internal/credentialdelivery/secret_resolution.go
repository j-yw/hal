package credentialdelivery

// SecretMetadataResolver is the narrow broker boundary used by credential
// delivery planning. Implementations receive only a safe reference and must
// return only broker metadata, never secret values or provider details.
type SecretMetadataResolver interface {
	ResolveSecretReference(reference SecretReference) (BrokerSecretMetadata, bool, error)
}

// SecretResolutionRequest groups validated binding metadata with the broker
// metadata resolver used before delivery plan construction.
type SecretResolutionRequest struct {
	Bindings []Binding
	Resolver SecretMetadataResolver
}

// ResolveBindingSecretMetadata resolves safe binding secret references to
// broker metadata and fails closed if any reference is missing, unsafe, or
// rejected by the resolver.
func ResolveBindingSecretMetadata(request SecretResolutionRequest) SecretResolutionResult {
	result := SecretResolutionResult{Valid: true}
	if request.Bindings != nil {
		result.Bindings = []ResolvedBindingSecretMetadata{}
	}

	bindings := NormalizeBindingMetadataRecords(request.Bindings)
	if len(bindings) == 0 {
		return result
	}
	if request.Resolver == nil {
		for i, binding := range bindings {
			result.addResolutionError(resolutionErrorRequest{
				Binding: binding,
				Index:   i,
				Code:    ErrorResolverFailed,
				Field:   "resolver",
				Reason:  ReasonUnknown,
			})
		}
		result.Valid = false
		return SanitizeSecretResolutionResult(result)
	}

	resolvedByRef := make(map[string]BrokerSecretMetadata, len(bindings))
	for i, binding := range bindings {
		bindingResult := ValidateBindingMetadata(binding)
		if !bindingResult.Valid {
			for _, err := range bindingResult.Errors {
				result.addResolutionError(resolutionErrorRequest{
					Binding: binding,
					Index:   i,
					Code:    err.Code,
					Field:   resolutionBindingField(err.Field),
					Reason:  err.ReasonCode,
				})
			}
			continue
		}

		brokerSecret, ok := resolvedByRef[binding.SecretRef]
		if !ok {
			var found bool
			var err error
			brokerSecret, found, err = request.Resolver.ResolveSecretReference(SanitizeSecretReferenceMetadata(SecretReference{
				BindingID: binding.ID,
				SecretRef: binding.SecretRef,
			}))
			if err != nil {
				result.addResolutionError(resolutionErrorRequest{
					Binding: binding,
					Index:   i,
					Code:    ErrorResolverFailed,
					Field:   "bindings.secretRef",
					Reason:  ReasonUnknown,
				})
				continue
			}
			brokerSecret = SanitizeBrokerSecretMetadata(brokerSecret)
			if !found {
				result.addMissingSecretReference(binding, i)
				continue
			}
			if brokerSecret.ID == "" {
				result.addResolutionError(resolutionErrorRequest{
					Binding: binding,
					Index:   i,
					Code:    ErrorUnsafeReference,
					Field:   "brokerSecret.id",
					Reason:  ReasonMissingSecretReference,
				})
				continue
			}
			if !brokerSecret.Present {
				result.addMissingSecretReference(binding, i)
				continue
			}
			if brokerSecret.ID != binding.SecretRef {
				result.addResolutionError(resolutionErrorRequest{
					Binding: binding,
					Index:   i,
					Code:    ErrorUnsafeReference,
					Field:   "brokerSecret.id",
					Reason:  ReasonMissingSecretReference,
				})
				continue
			}
			resolvedByRef[binding.SecretRef] = brokerSecret
		}

		result.Bindings = append(result.Bindings, ResolvedBindingSecretMetadata{
			BindingID:    binding.ID,
			SecretRef:    binding.SecretRef,
			DeliveryMode: binding.DeliveryMode,
			BrokerSecret: brokerSecret,
		})
	}

	result.Valid = len(result.Errors) == 0
	return SanitizeSecretResolutionResult(result)
}

type resolutionErrorRequest struct {
	Binding Binding
	Index   int
	Code    ErrorCode
	Field   string
	Reason  ReasonCode
}

func (r *SecretResolutionResult) addMissingSecretReference(binding Binding, index int) {
	r.addResolutionError(resolutionErrorRequest{
		Binding: binding,
		Index:   index,
		Code:    ErrorMissingSecretReference,
		Field:   "bindings.secretRef",
		Reason:  ReasonMissingSecretReference,
	})
	r.Warnings = append(r.Warnings, Warning{
		Code:       WarningBindingOmitted,
		ReasonCode: ReasonMissingSecretReference,
		BindingID:  binding.ID,
		Mode:       binding.DeliveryMode,
	})
}

func (r *SecretResolutionResult) addResolutionError(request resolutionErrorRequest) {
	index := request.Index
	r.Errors = append(r.Errors, SanitizedError{
		Code:       request.Code,
		Field:      request.Field,
		BindingID:  request.Binding.ID,
		Mode:       request.Binding.DeliveryMode,
		Index:      &index,
		ReasonCode: request.Reason,
	})
}

func resolutionBindingField(field string) string {
	if field == "" {
		return "bindings"
	}
	return "bindings." + field
}
