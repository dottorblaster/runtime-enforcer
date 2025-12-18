package policygenerator

import (
	"fmt"
	"log/slog"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	cmCache "sigs.k8s.io/controller-runtime/pkg/cache"
)

const (
	policyLabelKey = "security.rancher.io/policy"
)

type policyID = uint64

type PolicyGenerator struct {
	logger               *slog.Logger
	resolver             *resolver.Resolver
	nextPolicyID         policyID
	policyValuesFunc     func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error
	policyModeUpdateFunc func(policyID uint64, mode policymode.Mode, op bpf.PolicyModeOperation) error
	wpState              map[string]map[string]policyID
}

func SetupPolicyGenerator(
	logger *slog.Logger,
	informer cmCache.Informer,
	resolver *resolver.Resolver,
	policyValuesFunc func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error,
	policyModeUpdateFunc func(policyID uint64, mode policymode.Mode, op bpf.PolicyModeOperation) error,
) {
	p := &PolicyGenerator{
		logger:               logger.With("component", "policy-generator"),
		resolver:             resolver,
		nextPolicyID:         1,
		policyValuesFunc:     policyValuesFunc,
		wpState:              make(map[string]map[string]policyID),
		policyModeUpdateFunc: policyModeUpdateFunc,
	}
	// We deliberately ignore the returned cache.ResourceEventHandlerRegistration and error here because
	// we don't need to remove the handler for the lifetime of the daemon and informer construction
	// already succeeded.
	_, _ = informer.AddEventHandler(p.EventHandlers())
}

func (p *PolicyGenerator) allocPolicyID() policyID {
	id := p.nextPolicyID
	p.nextPolicyID++
	return id
}

func resourceCheck(logger *slog.Logger, prefix string, obj interface{}) *securityv1alpha1.WorkloadPolicy {
	wp, ok := obj.(*securityv1alpha1.WorkloadPolicy)
	if !ok {
		logger.Error("unexpected object type", "method", prefix, "object", obj)
		return nil
	}
	return wp
}

func (p *PolicyGenerator) addPolicy(wp *securityv1alpha1.WorkloadPolicy) error {
	p.logger.Info(
		"handler called",
		"method", "add-policy",
		"policy-name", wp.Name,
		"policy-namespace", wp.Namespace,
	)
	wpKey := wp.Namespace + "/" + wp.Name
	if _, exists := p.wpState[wpKey]; exists {
		return fmt.Errorf("workload policy already exists in internal state: %s", wpKey)
	}

	p.wpState[wpKey] = make(map[string]policyID, len(wp.Spec.RulesByContainer))

	for containerName, containerRules := range wp.Spec.RulesByContainer {
		polID := p.allocPolicyID()
		p.logger.Info("create policy", "id", polID, "wp", wpKey)

		// Populate policy values
		if err := p.policyValuesFunc(polID, containerRules.Executables.Allowed, bpf.AddValuesToPolicy); err != nil {
			return fmt.Errorf("failed to populate policy values for wp %s, container %s: %w", wpKey, containerName, err)
		}

		// Set policy mode
		mode := policymode.ParseMode(wp.Spec.Mode)
		if err := p.policyModeUpdateFunc(polID, mode, bpf.UpdateMode); err != nil {
			return fmt.Errorf("failed to set policy mode '%s' for wp %s, container %s: %w",
				mode.String(), wpKey, containerName, err)
		}

		// update the map with the policy ID
		p.wpState[wpKey][containerName] = polID

		containerSelector := &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "name",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{containerName},
				},
			},
		}
		podSelector := &metav1.LabelSelector{
			MatchLabels: map[string]string{
				policyLabelKey: wp.Name,
			},
		}

		if err := p.resolver.AddPolicy(polID, wp.Namespace, podSelector, containerSelector); err != nil {
			return fmt.Errorf("failed to add policy to resolver for wp %s, container %s: %w", wpKey, containerName, err)
		}
	}

	return nil
}

func (p *PolicyGenerator) updatePolicy(oldWp, newWp *securityv1alpha1.WorkloadPolicy) error {
	p.logger.Info(
		"handler called",
		"method", "update-policy",
		"policy-name", newWp.Name,
		"policy-namespace", newWp.Namespace,
	)

	// for now we only listen to mode updates
	// todo!: we also need to handle the change of values for a specific container
	if oldWp.Spec.Mode == newWp.Spec.Mode {
		return nil
	}

	p.logger.Info(
		"policy mode changed",
		"old-mode", oldWp.Spec.Mode,
		"new-mode", newWp.Spec.Mode,
		"wp", newWp.Name,
	)

	wpKey := newWp.Namespace + "/" + newWp.Name
	state, exists := p.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}

	mode := policymode.ParseMode(newWp.Spec.Mode)

	for containerName, policyID := range state {
		if err := p.policyModeUpdateFunc(policyID, mode, bpf.UpdateMode); err != nil {
			return fmt.Errorf("failed to set policy mode '%s' for wp %s, container %s: %w",
				mode.String(), newWp.Name, containerName, err)
		}
	}
	return nil
}

func (p *PolicyGenerator) deletePolicy(wp *securityv1alpha1.WorkloadPolicy) error {
	p.logger.Info(
		"handler called",
		"method", "delete",
		"policy-name", wp.Name,
		"policy-namespace", wp.Namespace,
	)

	wpKey := wp.Namespace + "/" + wp.Name
	state, exists := p.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}
	delete(p.wpState, wpKey)

	for containerName, policyID := range state {
		if err := p.policyValuesFunc(policyID, []string{}, bpf.RemoveValuesFromPolicy); err != nil {
			return fmt.Errorf("failed to remove policy values for wp %s, container %s: %w", wpKey, containerName, err)
		}

		if err := p.policyModeUpdateFunc(policyID, 0, bpf.DeleteMode); err != nil {
			return fmt.Errorf("failed to remove policy from policy mode map for wp %s, container %s: %w",
				wpKey, containerName, err)
		}

		if err := p.resolver.DeletePolicy(policyID); err != nil {
			return fmt.Errorf("failed to remove policy from cgroup map for wp %s, container %s: %w",
				wpKey, containerName, err)
		}
	}

	return nil
}

func (p *PolicyGenerator) EventHandlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wp := resourceCheck(p.logger, "add-policy", obj)
			if wp == nil {
				return
			}
			if err := p.addPolicy(wp); err != nil {
				// todo!: we need to populate an internal status to report the failure to the user
				p.logger.Error("failed to add policy", "error", err)
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newWp := resourceCheck(p.logger, "update-policy", newObj)
			if newWp == nil {
				return
			}
			oldWp := resourceCheck(p.logger, "update-policy", oldObj)
			if oldWp == nil {
				return
			}
			if err := p.updatePolicy(oldWp, newWp); err != nil {
				p.logger.Error("failed to update policy", "error", err)
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			wp := resourceCheck(p.logger, "delete-policy", obj)
			if wp == nil {
				return
			}
			if err := p.deletePolicy(wp); err != nil {
				p.logger.Error("failed to delete policy", "error", err)
				return
			}
		},
	}
}
