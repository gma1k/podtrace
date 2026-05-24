package nodespawn

import (
	"context"
	"fmt"
	"io"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// StartPortForward opens a TCP tunnel from localPort on the workstation to
// remotePort inside the named pod.
func StartPortForward(ctx context.Context, restCfg *rest.Config, clientset kubernetes.Interface, pod *corev1.Pod, localPort, remotePort int, stdout, stderr io.Writer) error {
	if pod == nil {
		return fmt.Errorf("nodespawn: nil pod")
	}
	roundTripper, upgrader, err := spdy.RoundTripperFor(restCfg)
	if err != nil {
		return fmt.Errorf("nodespawn: portforward roundtripper: %w", err)
	}

	req := clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Namespace(pod.Namespace).
		Name(pod.Name).
		SubResource("portforward")

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, "POST", req.URL())

	stopCh := make(chan struct{})
	readyCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stopCh)
	}()

	fw, err := portforward.New(dialer,
		[]string{fmt.Sprintf("%d:%d", localPort, remotePort)},
		stopCh, readyCh, stdout, stderr)
	if err != nil {
		return fmt.Errorf("nodespawn: portforward init: %w", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- fw.ForwardPorts() }()

	select {
	case <-readyCh:
	case err := <-errCh:
		return fmt.Errorf("nodespawn: portforward did not become ready: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}
