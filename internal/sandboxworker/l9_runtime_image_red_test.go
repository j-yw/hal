package sandboxworker

import (
	"context"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL9ClientDriverForwardsSelectedRuntimeImageToWorkerCreate(t *testing.T) {
	const selectedImage = "registry.test/hal/runtime:stable@sha256:dededededededededededededededededededededededededededededededededede"
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{DriverID: sandboxruntime.DriverRootlessPodman, Client: client})
	if err != nil {
		t.Fatalf("NewClientDriver() error = %v", err)
	}
	req := sandboxruntime.CreateRequest{Name: "runtime-l9"}
	setL9StructStringField(t, &req, "Image", selectedImage)

	if _, err := driver.Create(context.Background(), req); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if got := l9StructStringField(t, client.createReq, "Image"); got != selectedImage {
		t.Fatalf("worker create image = %q, want selected digest-pinned image", got)
	}
}

func TestL9WorkerServiceForwardsSelectedRuntimeImageToDriverCreate(t *testing.T) {
	const selectedImage = "registry.test/hal/runtime:stable@sha256:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
	driver := &l9RuntimeImageDriver{recordingLifecycleDriver: recordingLifecycleDriver{id: sandboxruntime.DriverRootlessPodman}}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error = %v", err)
	}
	service, err := NewService(ServiceOptions{WorkerID: "worker-l9", Registry: registry})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	req := CreateRequest{Name: "runtime-l9"}
	setL9StructStringField(t, &req, "Image", selectedImage)

	resp := service.HandleRequest(context.Background(), Request{
		RequestID: "request-l9",
		Operation: OperationCreate,
		DriverID:  sandboxruntime.DriverRootlessPodman,
		Create:    &req,
	})
	if err := resp.Validate(); err != nil {
		t.Fatalf("worker create response = %#v, error = %v", resp, err)
	}
	if driver.image != selectedImage {
		t.Fatalf("driver create image = %q, want selected digest-pinned image", driver.image)
	}
}

type l9RuntimeImageDriver struct {
	recordingLifecycleDriver
	image string
}

func (driver *l9RuntimeImageDriver) Create(ctx context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	driver.image = l9StructStringField(nil, req, "Image")
	return driver.recordingLifecycleDriver.Create(ctx, req)
}

func setL9StructStringField(t *testing.T, target any, fieldName, value string) {
	t.Helper()
	field := reflect.ValueOf(target).Elem().FieldByName(fieldName)
	if !field.IsValid() || field.Kind() != reflect.String || !field.CanSet() {
		t.Fatalf("%T.%s string field is required", target, fieldName)
	}
	field.SetString(value)
}

func l9StructStringField(t *testing.T, target any, fieldName string) string {
	if t != nil {
		t.Helper()
	}
	field := reflect.ValueOf(target).FieldByName(fieldName)
	if !field.IsValid() || field.Kind() != reflect.String {
		if t != nil {
			t.Fatalf("%T.%s string field is required", target, fieldName)
		}
		return ""
	}
	return field.String()
}
