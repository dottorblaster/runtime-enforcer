package resolver

type CgroupID = uint64
type ContainerID = string
type PodID = string
type ContainerName = string
type Labels map[string]string

type PodMeta struct {
	ID           PodID
	Namespace    string
	Name         string
	WorkloadName string
	WorkloadType string
	Labels       Labels
}

type ContainerMeta struct {
	ID       ContainerID
	Name     ContainerName
	CgroupID CgroupID
}
