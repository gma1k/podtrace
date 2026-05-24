package kubernetes

import (
	"context"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type PodResolverInterface interface {
	ResolvePod(ctx context.Context, podName, namespace, containerName string) (*PodInfo, error)
}

type ClientsetProvider interface {
	GetClientset() kubernetes.Interface
}

type RestConfigProvider interface {
	GetRestConfig() *rest.Config
}

