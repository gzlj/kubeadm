package main

import (
	"crypto"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/gzlj/kubeadm/cmd/kubeadm/app/phases/certs/renewal"
	kubeadmapi "github.com/gzlj/kubeadm/cmd/kubeadm/app/apis/kubeadm"
	renewal2 "github.com/gzlj/kubeadm/cmd/kubeadm/app/phases/renewal"
	certutil "k8s.io/client-go/util/cert"

	//kubeadmutil "github.com/gzlj/kubeadm/cmd/kubeadm/app/util"
	"github.com/gzlj/kubeadm/cmd/kubeadm/app/util/pkiutil"
	"github.com/pkg/errors"
	"io/ioutil"
	"k8s.io/client-go/tools/clientcmd"
	//"k8s.io/client-go/util/keyutil"
	//"k8s.io/klog"
	"strings"

	//"k8s.io/client-go/util/keyutil"
	//certutil "k8s.io/client-go/util/cert"
	//certsphase "github.com/gzlj/kubeadm/cmd/kubeadm/app/phases/certs"
	//"k8s.io/klog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	kubeconfigutil "github.com/gzlj/kubeadm/cmd/kubeadm/app/util/kubeconfig"
	"time"



	//"k8s.io/client-go/tools/clientcmd/api"
	//"k8s.io/client-go/tools/clientcmd/api/v1"
)

const (
	ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto
	ExtKeyUsageMicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigning

	// ECPrivateKeyBlockType is a possible value for pem.Block.Type.
	ECPrivateKeyBlockType = "EC PRIVATE KEY"
	// RSAPrivateKeyBlockType is a possible value for pem.Block.Type.
	RSAPrivateKeyBlockType = "RSA PRIVATE KEY"
	// PrivateKeyBlockType is a possible value for pem.Block.Type.
	PrivateKeyBlockType = "PRIVATE KEY"
	// PublicKeyBlockType is a possible value for pem.Block.Type.
	PublicKeyBlockType = "PUBLIC KEY"
)

var (
	Codec  runtime.Codec
	Scheme *runtime.Scheme
)


func init() {
	/*Scheme = runtime.NewScheme()
	utilruntime.Must(api.AddToScheme(Scheme))
	utilruntime.Must(v1.AddToScheme(Scheme))
	yamlSerializer := json.NewYAMLSerializer(json.DefaultMetaFactory, Scheme, Scheme)
	Codec = versioning.NewDefaultingCodecForScheme(
		Scheme,
		yamlSerializer,
		yamlSerializer,
		schema.GroupVersion{Version: Version},
		runtime.InternalGroupVersioner,
	)*/
}

type ExtKeyUsage int

func main () {

	rm, err := renewal2.NewManager(&kubeadmapi.ClusterConfiguration{}, "/etc/kubernetes")
	CheckErr(err)
	/*cmdList := []*cobra.Command{}
	funcList := []func(){}
*/
	kubeCaCert, kubeCaKey, _ := pkiutil.LoadCertificateAuthority("/etc/kubernetes/pki", "ca")
	etcdCaCert, etcdCaKey, _ := pkiutil.LoadCertificateAuthority("/etc/kubernetes/pki/etcd", "ca")
	frontProxyCaCert, frontProxyCaKey, _ := pkiutil.LoadCertificateAuthority("/etc/kubernetes/pki", "front-proxy-ca")

	kubeCaCfg := certToConfig(kubeCaCert)
	newKubeCaCert, _ := NewSelfSignedCACert(*kubeCaCfg, kubeCaKey)
	WriteCert("/etc/kubernetes/pki/ca.crt", pkiutil.EncodeCertPEM(newKubeCaCert))

	etcdCaCfg := certToConfig(etcdCaCert)
	newEtcdCaCert, _ := NewSelfSignedCACert(*etcdCaCfg, etcdCaKey)
	WriteCert("/etc/kubernetes/pki/etcd/ca.crt", pkiutil.EncodeCertPEM(newEtcdCaCert))

	frontProxyCaCfg := certToConfig(frontProxyCaCert)
	newFrontProxyCaCert, _ := NewSelfSignedCACert(*frontProxyCaCfg, frontProxyCaKey)
	WriteCert("/etc/kubernetes/pki/front-proxy-ca.crt", pkiutil.EncodeCertPEM(newFrontProxyCaCert))


	// /etc/kuberntetes/kubelet.conf
	hostname, _ := os.Hostname()
	kubeletClientName := fmt.Sprintf("%s%s", "system:node:", hostname)
	fileName := filepath.Join("/etc/kubernetes/", "kubelet.conf")
	config, _ := clientcmd.LoadFromFile(fileName)
	expectedCtx := config.CurrentContext
	expectedCluster := config.Contexts[expectedCtx].Cluster

	server := config.Clusters[expectedCluster].Server

	clientCertConfig := certutil.Config{
		CommonName:   kubeletClientName,
		Organization: []string{"system:nodes"},
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert, clientKey, _ := pkiutil.NewCertAndKey(kubeCaCert, kubeCaKey, &clientCertConfig)
	encodedClientKey, _ := MarshalPrivateKeyToPEM(clientKey)


	c :=kubeconfigutil.CreateWithCerts(
		server,
		expectedCluster,
		kubeletClientName,
		pkiutil.EncodeCertPEM(kubeCaCert),
		encodedClientKey,
		pkiutil.EncodeCertPEM(clientCert),
	)

	_ = kubeconfigutil.WriteToDisk("/etc/kubernetes/kubelet.conf", c)





	for _, handler := range rm.Certificates() {
		renewCert(handler)
		// get the cobra.Command skeleton for this command


	/*	// get the implementation of renewing this certificate
		renewalFunc := func(handler *renewal.CertificateRenewHandler) func() {
			return func() { renewCert(handler) }
		}(handler)
		cmdList = append(cmdList, cmd)
		// Collect renewal functions for `renew all`
		funcList = append(funcList, renewalFunc)*/
	}

}

func renewCert(handler *renewal2.CertificateRenewHandler) {
	rm, err := renewal.NewManager(&kubeadmapi.ClusterConfiguration{}, "/etc/kubernetes")
	renewed, err := rm.RenewUsingLocalCA(handler.Name)
	CheckErr(err)
	if !renewed {
		fmt.Printf("Detected external %s, %s can't be renewed\n", handler.CABaseName, handler.LongName)
		return
	}
	fmt.Printf("%s renewed\n", handler.LongName)
}

func certToConfig(cert *x509.Certificate) *Config {
	return &Config{
		CommonName:   cert.Subject.CommonName,
		Organization: cert.Subject.Organization,
		Usages: cert.ExtKeyUsage,
	}
}

type Config struct {
	CommonName   string
	Organization []string
	AltNames     AltNames
	Usages       []x509.ExtKeyUsage
}
type AltNames struct {
	DNSNames []string
	IPs      []net.IP
}


func NewSelfSignedCACert(cfg Config, key crypto.Signer) (*x509.Certificate, error) {
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(time.Hour * 24 * 365 * 100).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

func WriteCert(certPath string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(certPath), os.FileMode(0755)); err != nil {
		return err
	}
	return ioutil.WriteFile(certPath, data, os.FileMode(0644))
}
/*
func LoadFromFile(filename string) (*clientcmdapi.Config, error) {
	kubeconfigBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	config, err := Load(kubeconfigBytes)
	if err != nil {
		return nil, err
	}
	klog.V(6).Infoln("Config loaded from file: ", filename)

	// set LocationOfOrigin on every Cluster, User, and Context
	for key, obj := range config.AuthInfos {
		obj.LocationOfOrigin = filename
		config.AuthInfos[key] = obj
	}
	for key, obj := range config.Clusters {
		obj.LocationOfOrigin = filename
		config.Clusters[key] = obj
	}
	for key, obj := range config.Contexts {
		obj.LocationOfOrigin = filename
		config.Contexts[key] = obj
	}

	if config.AuthInfos == nil {
		config.AuthInfos = map[string]*clientcmdapi.AuthInfo{}
	}
	if config.Clusters == nil {
		config.Clusters = map[string]*clientcmdapi.Cluster{}
	}
	if config.Contexts == nil {
		config.Contexts = map[string]*clientcmdapi.Context{}
	}

	return config, nil
}*/

func CheckErr(err error) {
	checkErr(err, fatal)
}
func checkErr(err error, handleErr func(string, int)) {
	switch err.(type) {
	case nil:
		return
	default:
		handleErr(err.Error(), 1)
	}
}
func fatal(msg string, code int) {
	if len(msg) > 0 {
		// add newline if needed
		if !strings.HasSuffix(msg, "\n") {
			msg += "\n"
		}

		fmt.Fprint(os.Stderr, msg)
	}
	os.Exit(code)
}

func MarshalPrivateKeyToPEM(privateKey crypto.PrivateKey) ([]byte, error) {
	switch t := privateKey.(type) {
	case *ecdsa.PrivateKey:
		derBytes, err := x509.MarshalECPrivateKey(t)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  ECPrivateKeyBlockType,
			Bytes: derBytes,
		}
		return pem.EncodeToMemory(block), nil
	case *rsa.PrivateKey:
		block := &pem.Block{
			Type:  RSAPrivateKeyBlockType,
			Bytes: x509.MarshalPKCS1PrivateKey(t),
		}
		return pem.EncodeToMemory(block), nil
	default:
		return nil, fmt.Errorf("private key is not a recognized type: %T", privateKey)
	}
}
/*
func LoadFromFile(filename string) (*KubeconfigConfig, error) {
	kubeconfigBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	config, err := Load(kubeconfigBytes)
	if err != nil {
		return nil, err
	}
	klog.V(6).Infoln("Config loaded from file: ", filename)

	// set LocationOfOrigin on every Cluster, User, and Context
	for key, obj := range config.AuthInfos {
		obj.LocationOfOrigin = filename
		config.AuthInfos[key] = obj
	}
	for key, obj := range config.Clusters {
		obj.LocationOfOrigin = filename
		config.Clusters[key] = obj
	}
	for key, obj := range config.Contexts {
		obj.LocationOfOrigin = filename
		config.Contexts[key] = obj
	}

	if config.AuthInfos == nil {
		config.AuthInfos = map[string]*clientcmdapi.AuthInfo{}
	}
	if config.Clusters == nil {
		config.Clusters = map[string]*clientcmdapi.Cluster{}
	}
	if config.Contexts == nil {
		config.Contexts = map[string]*clientcmdapi.Context{}
	}

	return config, nil
}*/
/*
func Load(data []byte) (*KubeconfigConfig, error) {
	config := NewConfig()
	// if there's no data in a file, return the default object instead of failing (DecodeInto reject empty input)
	if len(data) == 0 {
		return config, nil
	}
	decoded, _, err := Codec.Decode(data, &schema.GroupVersionKind{Version: clientcmdlatest.Version, Kind: "Config"}, config)
	if err != nil {
		return nil, err
	}

	return decoded.(*KubeconfigConfig), nil
}
*/
func NewConfig() *KubeconfigConfig {
	return &KubeconfigConfig{
		//Preferences: *NewPreferences(),
		Clusters:    make(map[string]*Cluster),
		AuthInfos:   make(map[string]*AuthInfo),
		Contexts:    make(map[string]*Context),
		//Extensions:  make(map[string]runtime.Object),
	}
}


type KubeconfigConfig struct {
	// Legacy field from pkg/api/types.go TypeMeta.
	// TODO(jlowdermilk): remove this after eliminating downstream dependencies.
	// +optional
	Kind string `json:"kind,omitempty"`
	// Legacy field from pkg/api/types.go TypeMeta.
	// TODO(jlowdermilk): remove this after eliminating downstream dependencies.
	// +optional
	APIVersion string `json:"apiVersion,omitempty"`
	// Preferences holds general information to be use for cli interactions
	Preferences Preferences `json:"preferences"`
	// Clusters is a map of referencable names to cluster configs
	Clusters map[string]*Cluster `json:"clusters"`
	// AuthInfos is a map of referencable names to user configs
	AuthInfos map[string]*AuthInfo `json:"users"`
	// Contexts is a map of referencable names to context configs
	Contexts map[string]*Context `json:"contexts"`
	// CurrentContext is the name of the context that you would like to use by default
	CurrentContext string `json:"current-context"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
}

type Preferences struct {
	// +optional
	Colors bool `json:"colors,omitempty"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
	//Extensions map[string]runtime.Object `json:"extensions,omitempty"`
}

type Cluster struct {
	// LocationOfOrigin indicates where this object came from.  It is used for round tripping config post-merge, but never serialized.
	LocationOfOrigin string
	// Server is the address of the kubernetes cluster (https://hostname:port).
	Server string `json:"server"`
	// InsecureSkipTLSVerify skips the validity check for the server's certificate. This will make your HTTPS connections insecure.
	// +optional
	InsecureSkipTLSVerify bool `json:"insecure-skip-tls-verify,omitempty"`
	// CertificateAuthority is the path to a cert file for the certificate authority.
	// +optional
	CertificateAuthority string `json:"certificate-authority,omitempty"`
	// CertificateAuthorityData contains PEM-encoded certificate authority certificates. Overrides CertificateAuthority
	// +optional
	CertificateAuthorityData []byte `json:"certificate-authority-data,omitempty"`
// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
// +optional
}

type AuthInfo struct {
	// LocationOfOrigin indicates where this object came from.  It is used for round tripping config post-merge, but never serialized.
	LocationOfOrigin string
	// ClientCertificate is the path to a client cert file for TLS.
	// +optional
	ClientCertificate string `json:"client-certificate,omitempty"`
	// ClientCertificateData contains PEM-encoded data from a client cert file for TLS. Overrides ClientCertificate
	// +optional
	ClientCertificateData []byte `json:"client-certificate-data,omitempty"`
	// ClientKey is the path to a client key file for TLS.
	// +optional
	ClientKey string `json:"client-key,omitempty"`
	// ClientKeyData contains PEM-encoded data from a client key file for TLS. Overrides ClientKey
	// +optional
	ClientKeyData []byte `json:"client-key-data,omitempty"`
	// Token is the bearer token for authentication to the kubernetes cluster.
	// +optional
	Token string `json:"token,omitempty"`
	// TokenFile is a pointer to a file that contains a bearer token (as described above).  If both Token and TokenFile are present, Token takes precedence.
	// +optional
	TokenFile string `json:"tokenFile,omitempty"`
	// Impersonate is the username to act-as.
	// +optional
	Impersonate string `json:"act-as,omitempty"`
	// ImpersonateGroups is the groups to imperonate.
	// +optional
	ImpersonateGroups []string `json:"act-as-groups,omitempty"`
	// ImpersonateUserExtra contains additional information for impersonated user.
	// +optional
	ImpersonateUserExtra map[string][]string `json:"act-as-user-extra,omitempty"`
	// Username is the username for basic authentication to the kubernetes cluster.
	// +optional
	Username string `json:"username,omitempty"`
	// Password is the password for basic authentication to the kubernetes cluster.
	// +optional
	Password string `json:"password,omitempty"`
	// AuthProvider specifies a custom authentication plugin for the kubernetes cluster.
	// +optional
	//AuthProvider *AuthProviderConfig `json:"auth-provider,omitempty"`
	// Exec specifies a custom exec-based authentication plugin for the kubernetes cluster.
	// +optional
	//Exec *ExecConfig `json:"exec,omitempty"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
	//Extensions map[string]runtime.Object `json:"extensions,omitempty"`
}
type Context struct {
	// LocationOfOrigin indicates where this object came from.  It is used for round tripping config post-merge, but never serialized.
	LocationOfOrigin string
	// Cluster is the name of the cluster for this context
	Cluster string `json:"cluster"`
	// AuthInfo is the name of the authInfo for this context
	AuthInfo string `json:"user"`
	// Namespace is the default namespace to use on unspecified requests
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
	//Extensions map[string]runtime.Object `json:"extensions,omitempty"`
}
/*
func LoadCertificateAuthority(pkiDir string, baseName string) (*x509.Certificate, crypto.Signer, error) {
	// Checks if certificate authority exists in the PKI directory
	if !pkiutil.CertOrKeyExist(pkiDir, baseName) {
		return nil, nil, errors.Errorf("couldn't load %s certificate authority from %s", baseName, pkiDir)
	}
	//pkiutil.CertOrKeyExist()

	// Try to load certificate authority .crt and .key from the PKI directory
	caCert, caKey, err := pkiutil.TryLoadCertAndKeyFromDisk(pkiDir, baseName)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failure loading %s certificate authority", baseName)
	}

	// Make sure the loaded CA cert actually is a CA
	if !caCert.IsCA {
		return nil, nil, errors.Errorf("%s certificate is not a certificate authority", baseName)
	}

	return caCert, caKey, nil
}*/