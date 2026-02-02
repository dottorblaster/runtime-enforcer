package resolver

import (
	"fmt"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"k8s.io/client-go/tools/cache"
)

type PolicyID = uint64
type policyByContainer = map[ContainerName]PolicyID
type namespacedPolicyName = string

const (
	// PolicyIDNone is used to indicate no policy associated with the cgroup.
	PolicyIDNone PolicyID = 0
)

// this must be called with the resolver lock held.
func (r *Resolver) allocPolicyID() PolicyID {
	id := r.nextPolicyID
	r.nextPolicyID++
	return id
}

// syncPolicyInBPF updates or clears policy values and mode in BPF for the given policy ID.
// For valuesOp AddValuesToPolicy or ReplaceValuesInPolicy: updates allowedBinaries and mode.
// For valuesOp RemoveValuesFromPolicy: clears policy values and mode.
// This must be called with the resolver lock held.
func (r *Resolver) syncPolicyInBPF(
	policyID PolicyID,
	allowedBinaries []string,
	mode policymode.Mode,
	valuesOp bpf.PolicyValuesOperation,
) error {
	binaries := allowedBinaries
	modeArg := mode
	modeOp := bpf.UpdateMode
	if valuesOp == bpf.RemoveValuesFromPolicy {
		binaries = []string{}
		modeArg = 0
		modeOp = bpf.DeleteMode
	}
	if err := r.policyUpdateBinariesFunc(policyID, binaries, valuesOp); err != nil {
		return err
	}
	if err := r.policyModeUpdateFunc(policyID, modeArg, modeOp); err != nil {
		return err
	}
	return nil
}

// this must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPod(state *podState, polByContainer policyByContainer) error {
	for _, container := range state.containers {
		polID, ok := polByContainer[container.name]
		if !ok {
			r.logger.Info("container unprotected",
				"namespace", state.podNamespace(),
				"pod name", state.podName(),
				"policy", state.policyLabel(),
				"container", container.name)
			continue
		}
		op := bpf.AddPolicyToCgroups
		if polID == PolicyIDNone {
			op = bpf.RemoveCgroups
		}
		if err := r.cgroupToPolicyMapUpdateFunc(polID, []CgroupID{container.cgID}, op); err != nil {
			return fmt.Errorf("failed to %s for pod %s, container %s, policy %s: %w",
				op.String(), state.podName(), container.name, state.policyLabel(), err)
		}
	}
	return nil
}

// this must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPodIfPresent(state *podState) error {
	policyName := state.policyLabel()

	// if the policy doesn't have the label we do nothing
	if policyName == "" {
		return nil
	}

	key := fmt.Sprintf("%s/%s", state.podNamespace(), policyName)
	pol, ok := r.wpState[key]
	if !ok {
		return fmt.Errorf(
			"pod has policy label but policy does not exist. pod-name: %s, pod-namespace: %s, policy-name: %s",
			state.podName(),
			state.podNamespace(),
			policyName,
		)
	}

	return r.applyPolicyToPod(state, pol)
}

// syncWorkloadPolicy ensures state and BPF maps match wp.Spec.RulesByContainer:
// allocates a policy ID for new containers, (re)applies binaries and mode for every container in the spec.
// If changes is non-nil, we will use it to track changes for the update operation.
// This must be called with the resolver lock held.
func (r *Resolver) syncWorkloadPolicy(wp *v1alpha1.WorkloadPolicy, changes policyByContainer) error {
	wpKey := wp.NamespacedName()
	mode := policymode.ParseMode(wp.Spec.Mode)
	state := r.wpState[wpKey]

	for containerName, containerRules := range wp.Spec.RulesByContainer {
		polID, hadPolicyID := state[containerName]
		if !hadPolicyID {
			polID = r.allocPolicyID()
			state[containerName] = polID
			if changes != nil {
				changes[containerName] = polID
			}
			r.logger.Info("create policy", "id", polID,
				"wp", wpKey,
				"container", containerName)
		}

		// Populate or replace policy values (Add for new policy ID, Replace for existing)
		op := bpf.ReplaceValuesInPolicy
		if !hadPolicyID {
			op = bpf.AddValuesToPolicy
		}
		if err := r.syncPolicyInBPF(polID, containerRules.Executables.Allowed, mode, op); err != nil {
			return fmt.Errorf("failed to populate policy for wp %s, container %s: %w", wpKey, containerName, err)
		}
	}
	return nil
}

// handleWPAdd adds a new workload policy into the resolver cache and applies the policies to all running pods that require it.
func (r *Resolver) handleWPAdd(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"add-wp-policy",
		"name", wp.Name,
		"namespace", wp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	wpKey := wp.NamespacedName()
	if _, exists := r.wpState[wpKey]; exists {
		return fmt.Errorf("workload policy already exists in internal state: %s", wpKey)
	}

	r.wpState[wpKey] = make(policyByContainer, len(wp.Spec.RulesByContainer))

	// Pass nil for add. No need to track changes as we will apply the full state to all matching pods.
	if err := r.syncWorkloadPolicy(wp, nil); err != nil {
		return err
	}

	wpMap := r.wpState[wpKey]
	// Now we search for pods that match the policy
	for _, podState := range r.podCache {
		if !podState.matchPolicy(wp.Name) {
			continue
		}

		if err := r.applyPolicyToPod(podState, wpMap); err != nil {
			return err
		}
	}
	return nil
}

// handleWPUpdate reinforces the workload policy from the current spec, removes containers
// that are no longer in the spec, then applies policy to all matching pods.
func (r *Resolver) handleWPUpdate(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"update-wp-policy",
		"name", wp.Name,
		"namespace", wp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	wpKey := wp.NamespacedName()
	state, exists := r.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}

	// changes: container -> PolicyID: add/keep for matching pods; container -> PolicyIDNone: remove.
	changes := make(policyByContainer)
	if err := r.syncWorkloadPolicy(wp, changes); err != nil {
		return err
	}

	// Containers removed from spec: cleanup BPF (policy values, mode) before deleting from state;
	// record PolicyIDNone in changes so applyPolicyToPod will remove cgroup associations.
	for containerName := range state {
		if _, stillPresent := wp.Spec.RulesByContainer[containerName]; stillPresent {
			continue
		}
		policyID := state[containerName]
		if err := r.syncPolicyInBPF(policyID, nil, 0, bpf.RemoveValuesFromPolicy); err != nil {
			return fmt.Errorf("failed to clear policy for wp %s, container %s: %w", wpKey, containerName, err)
		}
		changes[containerName] = PolicyIDNone
		delete(state, containerName)
	}

	for _, podState := range r.podCache {
		if !podState.matchPolicy(wp.Name) {
			continue
		}
		if err := r.applyPolicyToPod(podState, changes); err != nil {
			return err
		}
	}

	return nil
}

// handleWPDelete removes a workload policy from the resolver cache and updates the BPF maps accordingly.
func (r *Resolver) handleWPDelete(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"delete-wp-policy",
		"name", wp.Name,
		"namespace", wp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	wpKey := wp.NamespacedName()
	state, exists := r.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}
	delete(r.wpState, wpKey)

	for containerName, policyID := range state {
		// First we remove the association cgroupID -> PolicyID and then we will remove the policy values and modes

		// iteration + deletion on the ebpf map
		if err := r.cgroupToPolicyMapUpdateFunc(policyID, []CgroupID{}, bpf.RemovePolicy); err != nil {
			return fmt.Errorf("failed to remove policy from cgroup map: %w", err)
		}
		if err := r.syncPolicyInBPF(policyID, nil, 0, bpf.RemoveValuesFromPolicy); err != nil {
			return fmt.Errorf("failed to clear policy for wp %s, container %s: %w", wpKey, containerName, err)
		}
	}
	return nil
}

func resourceCheck(method string, obj interface{}) *v1alpha1.WorkloadPolicy {
	wp, ok := obj.(*v1alpha1.WorkloadPolicy)
	if !ok {
		panic(fmt.Sprintf("unexpected object type: method=%s, object=%v", method, obj))
	}
	return wp
}

func (r *Resolver) PolicyEventHandlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wp := resourceCheck("add-policy", obj)
			if wp == nil {
				return
			}
			if err := r.handleWPAdd(wp); err != nil {
				// todo!: we need to populate an internal status to report the failure to the user
				r.logger.Error("failed to add policy", "error", err)
				return
			}
		},
		UpdateFunc: func(_ interface{}, newObj interface{}) {
			wp := resourceCheck("update-policy", newObj)
			if wp == nil {
				return
			}
			if err := r.handleWPUpdate(wp); err != nil {
				r.logger.Error("failed to update policy", "error", err)
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			wp := resourceCheck("delete-policy", obj)
			if wp == nil {
				return
			}
			if err := r.handleWPDelete(wp); err != nil {
				r.logger.Error("failed to delete policy", "error", err)
				return
			}
		},
	}
}

// ListPolicies returns a list of all workload policies info.
func (r *Resolver) ListPolicies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	// todo!: in the future we should also provide the status of the policy not just the name
	policiesNames := make([]string, 0, len(r.wpState))
	for name := range r.wpState {
		policiesNames = append(policiesNames, name)
	}
	return policiesNames
}
