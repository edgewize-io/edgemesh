package util

import (
	"os"

	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"

	"github.com/kubeedge/edgemesh/pkg/apis/config/defaults"
	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
)

const (
	clusterName = "kubeedge-cluster"
	contextName = "kubeedge-context"
	userName    = "edgemesh"
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func GenerateKubeClientConfig(c *v1alpha1.KubeAPIConfig) *clientcmdv1.Config {
	// Get server address, prioritize environment variables (for edge authentication scenarios)
	serverAddr := c.MetaServer.Server
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		if port := os.Getenv("KUBERNETES_SERVICE_PORT"); port != "" {
			// Use environment variables to construct metaServer address
			scheme := "https"
			serverAddr = scheme + "://" + host + ":" + port
			klog.Infof("Using metaServer address from environment variables: %s", serverAddr)
		}
	}

	namedCluster := clientcmdv1.NamedCluster{
		Name: clusterName,
		Cluster: clientcmdv1.Cluster{
			Server: serverAddr,
		},
	}
	namedContext := clientcmdv1.NamedContext{
		Name: contextName,
		Context: clientcmdv1.Context{
			Cluster:  clusterName,
			AuthInfo: userName,
		},
	}
	namedAuthInfo := clientcmdv1.NamedAuthInfo{
		Name:     userName,
		AuthInfo: clientcmdv1.AuthInfo{},
	}

	if c.MetaServer.Security.RequireAuthorization {
		// Use ServiceAccount token for authentication
		namedAuthInfo.AuthInfo.TokenFile = saTokenPath

		if c.MetaServer.Security.InsecureSkipTLSVerify {
			// Skip TLS verification (not recommended for production)
			namedCluster.Cluster.InsecureSkipTLSVerify = true
		} else {
			// Use CA certificate to verify server certificate
			namedCluster.Cluster.CertificateAuthority = c.MetaServer.Security.TLSCaFile

			// Optional: Client certificate for mutual TLS (if metaServer requires it)
			// Note: ServiceAccount authentication typically only needs CA cert + token
			// Client certificate is only needed for mutual TLS scenarios
			if c.MetaServer.Security.TLSCertFile != "" && c.MetaServer.Security.TLSPrivateKeyFile != "" {
				namedAuthInfo.AuthInfo.ClientCertificate = c.MetaServer.Security.TLSCertFile
				namedAuthInfo.AuthInfo.ClientKey = c.MetaServer.Security.TLSPrivateKeyFile
			}
		}
	}

	return &clientcmdv1.Config{
		APIVersion:     "v1",
		Kind:           "Config",
		Clusters:       []clientcmdv1.NamedCluster{namedCluster},
		Contexts:       []clientcmdv1.NamedContext{namedContext},
		CurrentContext: contextName,
		Preferences:    clientcmdv1.Preferences{},
		AuthInfos:      []clientcmdv1.NamedAuthInfo{namedAuthInfo},
	}
}

func SaveKubeConfigFile(kubeClientConfig *clientcmdv1.Config) error {
	data, err := yaml.Marshal(kubeClientConfig)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(defaults.TempKubeConfigPath, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer func() {
		err = f.Close()
		if err != nil {
			klog.ErrorS(err, "close file error")
		}
	}()

	_, err = f.Write(data)
	if err != nil {
		return err
	}

	return nil
}
