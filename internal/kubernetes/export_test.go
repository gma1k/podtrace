package kubernetes

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func NewPodResolverForTesting(clientset kubernetes.Interface) *PodResolver {
	return &PodResolver{
		clientset: clientset,
	}
}

func (ic *InformerCache) firstPodInformer() cache.SharedIndexInformer {
	if infs := ic.podInformers(); len(infs) > 0 {
		return infs[0]
	}
	return nil
}

func (ic *InformerCache) firstEndpointSliceInformer() cache.SharedIndexInformer {
	if infs := ic.endpointSliceInformers(); len(infs) > 0 {
		return infs[0]
	}
	return nil
}
