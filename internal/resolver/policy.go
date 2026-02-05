package resolver

import (
	"fmt"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"k8s.io/client-go/tools/cache"
)

type (
	PolicyID             = uint64
	policyByContainer    = map[ContainerName]PolicyID
	namespacedPolicyName = string
)

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

// upsertPolicy adds or updates all entries for the given policy ID in BPF maps.
// This must be called with the resolver lock held.
func (r *Resolver) upsertPolicy(
	policyID PolicyID,
	allowedBinaries []string,
	mode policymode.Mode,
	valuesOp bpf.PolicyValuesOperation,
) error {
	if err := r.policyUpdateBinariesFunc(policyID, allowedBinaries, valuesOp); err != nil {
		return err
	}
	if err := r.policyModeUpdateFunc(policyID, mode, bpf.UpdateMode); err != nil {
		return err
	}
	return nil
}

// removePolicy removes all entries for the given policy ID from BPF maps.
// This must be called with the resolver lock held.
func (r *Resolver) removePolicy(policyID PolicyID) error {
	// TODO: refactor the PolicyUpdateBinariesFunc to not collapse the add and replace
	// operations behind the same API. By doing that we will not need to pass a dummy values slice here.
	if err := r.policyUpdateBinariesFunc(policyID, nil, bpf.RemoveValuesFromPolicy); err != nil {
		return err
	}
	// TODO: refactor the PolicyModeUpdateFunc to not collapse the update and delete operations
	// behind the same API. By doing that we will not need to pass a dummy mode value here.
	if err := r.policyModeUpdateFunc(policyID, 0, bpf.DeleteMode); err != nil {
		return err
	}
	return nil
}

// applyPolicyToPod applies the given policy-by-container (add/update) to the pod's cgroups.
// This must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPod(state *podState, applied policyByContainer) error {
	for _, container := range state.containers {
		polID, ok := applied[container.name]
		if !ok {
			// No entry for this container: either not in policy, or unchanged.
			continue
		}
		if err := r.cgroupToPolicyMapUpdateFunc(polID, []CgroupID{container.cgID}, bpf.AddPolicyToCgroups); err != nil {
			return fmt.Errorf("failed to add policy to cgroups for pod %s, container %s, policy %s: %w",
				state.podName(), container.name, state.policyLabel(), err)
		}
	}
	return nil
}

// removePolicyFromPod removes cgroup→policyID associations for the given containers in the pod.
// It is used to remove policy from containers that are no longer in the spec.
// This must be called with the resolver lock held.
func (r *Resolver) removePolicyFromPod(
	wpKey namespacedPolicyName,
	podState *podState,
	wpState, removed policyByContainer,
) error {
	for _, container := range podState.containers {
		policyID, ok := removed[container.name]
		if !ok {
			continue
		}
		if err := r.cgroupToPolicyMapUpdateFunc(PolicyIDNone, []CgroupID{container.cgID}, bpf.RemoveCgroups); err != nil {
			return fmt.Errorf("failed to remove cgroups for pod %s, container %s, policy %s: %w",
				podState.podName(), container.name, podState.policyLabel(), err)
		}
		if err := r.removePolicy(policyID); err != nil {
			return fmt.Errorf("failed to clear policy for wp %s, container %s: %w", wpKey, container.name, err)
		}
		delete(wpState, container.name)
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
// It returns the container→policyID map for newly created policy IDs.
// This must be called with the resolver lock held.
func (r *Resolver) syncWorkloadPolicy(wp *v1alpha1.WorkloadPolicy) (policyByContainer, error) {
	wpKey := wp.NamespacedName()
	mode := policymode.ParseMode(wp.Spec.Mode)
	state := r.wpState[wpKey]
	newContainers := make(policyByContainer)

	for containerName, containerRules := range wp.Spec.RulesByContainer {
		polID, hadPolicyID := state[containerName]
		op := bpf.ReplaceValuesInPolicy
		if !hadPolicyID {
			polID = r.allocPolicyID()
			newContainers[containerName] = polID
			r.logger.Info("create policy", "id", polID,
				"wp", wpKey,
				"container", containerName)
			op = bpf.AddValuesToPolicy
		}
		if err := r.upsertPolicy(polID, containerRules.Executables.Allowed, mode, op); err != nil {
			return nil, fmt.Errorf("failed to populate policy for wp %s, container %s: %w", wpKey, containerName, err)
		}
	}

	return newContainers, nil
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

	state := make(policyByContainer, len(wp.Spec.RulesByContainer))
	r.wpState[wpKey] = state
	var err error
	var newContainers policyByContainer
	if newContainers, err = r.syncWorkloadPolicy(wp); err != nil {
		return err
	}
	for containerName, policyID := range newContainers {
		state[containerName] = policyID
	}

	// Now we search for pods that match the policy
	for _, podState := range r.podCache {
		if !podState.matchPolicy(wp.Name) {
			continue
		}

		if err = r.applyPolicyToPod(podState, state); err != nil {
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
	newContainers, err := r.syncWorkloadPolicy(wp)
	if err != nil {
		return err
	}
	for containerName, policyID := range newContainers {
		state[containerName] = policyID
	}

	// Split state into applied (still in spec) vs removed (no longer in spec).
	appliedMap := make(policyByContainer, len(wp.Spec.RulesByContainer))
	removedMap := make(policyByContainer, len(state))
	for containerName := range state {
		if _, stillPresent := wp.Spec.RulesByContainer[containerName]; stillPresent {
			appliedMap[containerName] = state[containerName]
		} else {
			removedMap[containerName] = state[containerName]
		}
	}

	// Update each matching pod: first remove policy for dropped containers, then apply for the rest.
	for _, podState := range r.podCache {
		if !podState.matchPolicy(wp.Name) {
			continue
		}
		if err = r.removePolicyFromPod(wpKey, podState, state, removedMap); err != nil {
			return err
		}
		if err = r.applyPolicyToPod(podState, appliedMap); err != nil {
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
		if err := r.removePolicy(policyID); err != nil {
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
