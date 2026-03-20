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

type ContainerInput struct {
	ContainerMeta

	CgroupPath string
}

type PodInput struct {
	Meta       PodMeta
	Containers map[ContainerID]ContainerInput
}

type PodView struct {
	Meta       PodMeta
	Containers map[ContainerID]ContainerMeta
}

type ContainerView struct {
	Meta    ContainerMeta
	PodMeta PodMeta
}
