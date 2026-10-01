package sandboxworker

import "testing"

func TestL8D6WorkerCredentialBindingBoundIsSixteen(t *testing.T) {
	request := l8WorkerV2StartRequest()
	request.SourceReferenceIDs = make([]string, 17)
	request.Bindings = make([]JobCredentialBindingV2, 17)
	for index := 0; index < 17; index++ {
		bindingID := "binding-" + string(rune('a'+index))
		sourceID := "source-" + string(rune('a'+index))
		request.SourceReferenceIDs[index] = sourceID
		request.Bindings[index] = JobCredentialBindingV2{BindingID: bindingID, SourceReferenceID: sourceID, Mode: CredentialModeFileTmpfs}
	}
	if request.Validate() == nil {
		t.Fatal("worker request accepted seventeen credential bindings")
	}
}

func TestL8D6WorkerCredentialBindingBoundAcceptsExactlySixteen(t *testing.T) {
	request := l8WorkerV2StartRequest()
	request.SourceReferenceIDs = make([]string, 16)
	request.Bindings = make([]JobCredentialBindingV2, 16)
	for index := 0; index < 16; index++ {
		bindingID := "binding-" + string(rune('a'+index))
		sourceID := "source-" + string(rune('a'+index))
		request.SourceReferenceIDs[index] = sourceID
		request.Bindings[index] = JobCredentialBindingV2{BindingID: bindingID, SourceReferenceID: sourceID, Mode: CredentialModeFileTmpfs}
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("worker request rejected exactly sixteen credential bindings: %v", err)
	}
}
