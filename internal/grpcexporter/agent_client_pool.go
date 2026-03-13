package grpcexporter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type nodeName = string

type AgentClientPoolConfig struct {
	AgentFactoryConfig

	Namespace           string
	LabelSelectorString string
	Logger              *slog.Logger
}

// AgentClientPool offers APIs to call a GRPC query on each agent pod in the cluster.
type AgentClientPool struct {
	// this map always represent the node status, so it's possible that for a nodeName the client is nil
	clients       map[nodeName]AgentClientAPI
	namespace     string
	labelSelector map[string]string
	factory       *AgentClientFactory
	logger        *slog.Logger
}

func convertLabelStringToSelector(labelString string) (map[string]string, error) {
	agentLabelSelector := make(map[string]string)
	labels := strings.SplitSeq(labelString, ",")
	for label := range labels {
		parts := strings.Split(label, "=")
		if len(parts) != 2 { //nolint:mnd // label is composed of 2 parts
			return nil, fmt.Errorf("label should be in the format 'key=value': %s. Invalid selector %s",
				label,
				labelString)
		}
		agentLabelSelector[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return agentLabelSelector, nil
}

func getNamespace() (string, error) {
	const namespaceNamePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	// Get the agent namespace from the system.
	// We suppose we are always running inside the same namespace of the agent.
	data, err := os.ReadFile(namespaceNamePath)
	if err != nil {
		return "", fmt.Errorf("failed to read namespace file: %w", err)
	}
	namespace := string(data)
	if namespace == "" {
		return "", errors.New("empty agent namespace")
	}
	return namespace, nil
}

func NewAgentClientPool(poolConf AgentClientPoolConfig) (*AgentClientPool, error) {
	labelSelector, err := convertLabelStringToSelector(poolConf.LabelSelectorString)
	if err != nil {
		return nil, fmt.Errorf("failed to convert agent label selector: %w", err)
	}

	// This is mainly for testing purposes.
	if poolConf.Namespace == "" {
		poolConf.Namespace, err = getNamespace()
		if err != nil {
			return nil, fmt.Errorf("failed to get agent namespace: %w", err)
		}
	}

	factory, err := NewAgentClientFactory(&poolConf.AgentFactoryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent client factory: %w", err)
	}

	return &AgentClientPool{
		clients:       make(map[nodeName]AgentClientAPI),
		namespace:     poolConf.Namespace,
		labelSelector: labelSelector,
		factory:       factory,
		logger:        poolConf.Logger,
	}, nil
}

// UpdatePool returns a map in this form:
// <nodeName> -> client
// For each agent pod it adds an entry with the pod's node name as the key and the agent client as the value.
// the client could be nil if we are not able to reach the GRPC server on the pod.
func (p *AgentClientPool) UpdatePool(ctx context.Context, reader client.Reader) (map[string]AgentClientAPI, error) {
	var podList corev1.PodList
	if err := reader.List(ctx, &podList,
		client.InNamespace(p.namespace),
		client.MatchingLabels(p.labelSelector),
	); err != nil {
		return nil, err
	}

	activeNodes := sets.New[nodeName]()
	for _, pod := range podList.Items {
		// even if the client will be nil we want to keep it in the activeNodes
		activeNodes.Insert(pod.Spec.NodeName)
		// Get or create the agent client for this pod
		if _, err := p.getOrCreateClient(&pod); err != nil {
			p.logger.WarnContext(ctx, "Failed to get or create agent client for pod", "pod", pod.Name, "error", err)
			continue
		}
	}

	// Check for stale clients
	for node, c := range p.clients {
		if activeNodes.Has(node) {
			continue
		}
		if c != nil {
			_ = c.Close()
		}
		delete(p.clients, node)
	}
	return p.clients, nil
}

func (p *AgentClientPool) getOrCreateClient(pod *corev1.Pod) (AgentClientAPI, error) {
	node := pod.Spec.NodeName
	agentClient, ok := p.clients[node]
	// it is possible that we have an entry but the client is nil
	if ok && agentClient != nil {
		// Client is already created and active
		return agentClient, nil
	}

	c, err := p.factory.NewClient(pod.Status.PodIP, pod.Name, pod.Namespace)
	if err != nil {
		p.clients[node] = nil
		return nil, fmt.Errorf("failed to create connection to pod %s: %w", pod.Name, err)
	}
	p.clients[node] = c
	return c, nil
}

func (p *AgentClientPool) MarkStaleAgentClient(nodeName nodeName) {
	client, ok := p.clients[nodeName]
	if !ok {
		return
	}
	// we close the client and we set it to nil
	if client != nil {
		_ = client.Close()
	}
	p.clients[nodeName] = nil
}
