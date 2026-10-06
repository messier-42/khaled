package cedar_test

import (
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

func TestForeignTimeAbsentAndErrorsDeny(t *testing.T) {
	req := policyengine.DecapsulateRequest{Principal: policyengine.Principal{URI: "p"}, AttributeSet: mustSet(t, nil), Now: time.Now(), OriginDomain: "origin", Federated: true}
	eng := mustEngine(t, `permit(principal, action, resource) when { context.federated && context.originDomain == "origin" && !(context has leaseTime) };`)
	got, err := eng.DecideDecapsulate(t.Context(), req)
	if err != nil || !got.Allow {
		t.Fatalf("explicit unknown-time permit: %+v %v", got, err)
	}
	eng = mustEngine(t, `permit(principal, action, resource); forbid(principal, action, resource) when { context.leaseTime < 1 };`)
	got, err = eng.DecideDecapsulate(t.Context(), req)
	if got.Allow {
		t.Fatalf("temporal forbid error allowed foreign access: %+v %v", got, err)
	}
}

func TestFederateRequiresSeparateTargetPermission(t *testing.T) {
	eng := mustEngine(t, `permit(principal, action == Action::"Encapsulate", resource); permit(principal, action == Action::"Federate", resource) when { context.targetDomain == "allowed" };`)
	for _, target := range []string{"allowed", "denied"} {
		got, err := eng.DecideFederate(t.Context(), policyengine.FederateRequest{Principal: policyengine.Principal{URI: "p"}, AttributeSet: mustSet(t, nil), TargetDomain: target, Now: time.Now()})
		if err != nil || got.Allow != (target == "allowed") {
			t.Fatalf("%s: %+v %v", target, got, err)
		}
	}
}

func TestFederateErrorInForbidFailsClosed(t *testing.T) {
	eng := mustEngine(t, `permit(principal, action, resource); forbid(principal, action, resource) when { context.missing == 1 };`)
	got, err := eng.DecideFederate(t.Context(), policyengine.FederateRequest{Principal: policyengine.Principal{URI: "p"}, AttributeSet: mustSet(t, nil), TargetDomain: "target"})
	if got.Allow || err == nil {
		t.Fatalf("erroneous forbid: %+v %v", got, err)
	}
}
