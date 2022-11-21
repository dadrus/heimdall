package kubernetes

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha1"
)

func TestFoo(t *testing.T) {
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	require.NoError(t, err)

	client, err := v1alpha1.NewClient(config)
	require.NoError(t, err)

	repo := client.RuleSetRepository("")
	rsl, err := repo.List(context.TODO(), metav1.ListOptions{})
	require.NoError(t, err)

	fmt.Printf("rule sets found: %+v\n", rsl)
}
