package plugin_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/config/schema"
	"github.com/messier-42/khaled/pkg/plugin"
)

const (
	unknownPlugin = "bogus"
	cedarEngine   = "cedar"
	diskPlugin    = "disk"
	fileSource    = "file"
)

type fakeIface interface {
	io.Closer
	ID() string
}

type fakeImpl struct{ id string }

func (f *fakeImpl) Close() error { return nil }
func (f *fakeImpl) ID() string   { return f.id }

type fakeArgs struct {
	Variant string
	Extra   string
}

func TestFactory_Register_And_Build(t *testing.T) {
	f := plugin.NewFactory[fakeArgs, fakeIface]("clientAuthn")
	f.Register("one", func(_ context.Context, a fakeArgs) (fakeIface, error) {
		return &fakeImpl{id: a.Extra}, nil
	}, nil)
	f.Register("two", func(_ context.Context, a fakeArgs) (fakeIface, error) {
		return &fakeImpl{id: "TWO:" + a.Extra}, nil
	}, nil)

	got, err := f.Build(context.Background(), "one", fakeArgs{Extra: "x"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got.ID() != "x" {
		t.Fatalf("ID = %q, want x", got.ID())
	}

	got, err = f.Build(context.Background(), "two", fakeArgs{Extra: "y"})
	if err != nil {
		t.Fatalf("Build two: %v", err)
	}
	if got.ID() != "TWO:y" {
		t.Fatalf("ID = %q, want TWO:y", got.ID())
	}
}

func TestFactory_Build_UnknownVariant(t *testing.T) {
	f := plugin.NewFactory[fakeArgs, fakeIface]("clientAuthn")
	_, err := f.Build(context.Background(), "nope", fakeArgs{})
	if err == nil || !strings.Contains(err.Error(), "unsupported clientAuthn plugin") {
		t.Fatalf("err: %v", err)
	}
}

func TestFactory_Build_PropagatesCtorError(t *testing.T) {
	f := plugin.NewFactory[fakeArgs, fakeIface]("fake")
	boom := errors.New("boom")
	f.Register("one", func(context.Context, fakeArgs) (fakeIface, error) { return nil, boom }, nil)

	_, err := f.Build(context.Background(), "one", fakeArgs{})
	if !errors.Is(err, boom) {
		t.Fatalf("err: %v, want %v", err, boom)
	}
}

func TestFactory_RegisterSchemas(t *testing.T) {
	var called int
	f := plugin.NewFactory[fakeArgs, fakeIface]("fake")
	f.Register("a", func(context.Context, fakeArgs) (fakeIface, error) { return nil, nil }, func(*schema.Registry) error {
		called++
		return nil
	})
	f.Register("b", func(context.Context, fakeArgs) (fakeIface, error) { return nil, nil }, func(*schema.Registry) error {
		called++
		return nil
	})

	reg := schema.New()
	if err := f.RegisterSchemas(reg); err != nil {
		t.Fatalf("RegisterSchemas: %v", err)
	}
	if called != 2 {
		t.Fatalf("schema callbacks fired %d times, want 2", called)
	}
}

func TestFactory_RegisterSchemas_StopsOnError(t *testing.T) {
	boom := errors.New("boom")
	f := plugin.NewFactory[fakeArgs, fakeIface]("fake")
	var called int
	f.Register("a", func(context.Context, fakeArgs) (fakeIface, error) { return nil, nil }, func(*schema.Registry) error {
		called++
		return boom
	})
	f.Register("b", func(context.Context, fakeArgs) (fakeIface, error) { return nil, nil }, func(*schema.Registry) error {
		called++
		return nil
	})
	reg := schema.New()
	if err := f.RegisterSchemas(reg); !errors.Is(err, boom) {
		t.Fatalf("err: %v, want %v", err, boom)
	}
	if called != 1 {
		t.Fatalf("called %d, want 1 (short-circuit)", called)
	}
}

func TestFactory_DuplicateRegisterPanics(t *testing.T) {
	f := plugin.NewFactory[fakeArgs, fakeIface]("fake")
	f.Register("a", func(context.Context, fakeArgs) (fakeIface, error) { return nil, nil }, nil)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	f.Register("a", func(context.Context, fakeArgs) (fakeIface, error) { return nil, nil }, nil)
}
