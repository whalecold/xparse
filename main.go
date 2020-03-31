package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"strings"

	"github.com/caicloud/clientset/kubernetes"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	recoverConfigClaimKey   = "recoverKey"
	recoverConfigClaimValue = "recoverValue"
)

var configPath = "~/.kube/config"
var day float64 = 365

func main() {
	flag.StringVar(&configPath, "kubeConfig", "~/.kube/config", "the config of kubernetes cluster")
	flag.Float64Var(&day, "day", 365, "the lease age of perm")
	flag.Parse()

	fmt.Printf("kubernetes config: [%s], min day: [%.0f]\n", configPath, day)
	client := generatorClient(configPath)
	nsList, err := client.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	//listSecret(client, nsList.Items)
	updateAllRelease(client, nsList.Items)
}

func updateAllRelease(client *kubernetes.Clientset, nss []corev1.Namespace) {
	for _, ns := range nss {
		if ns.Name == "default" || ns.Name == "kube-system" || ns.Name == "kube-public" {
			continue
		}
		fmt.Printf("----------start update release namespace %v-----------\n", ns.Name)
		rList, err := client.ReleaseV1alpha1().Releases(ns.Name).List(metav1.ListOptions{})
		if err != nil {
			panic(err)
		}
		for _, r := range rList.Items {
			if r.Annotations == nil {
				r.Annotations = map[string]string{}
			}
			fmt.Printf("start update namespace [%s] release name [%s]\n", ns.Name, r.Name)
			r.Annotations[recoverConfigClaimKey] = recoverConfigClaimValue
			newRelease, err := client.ReleaseV1alpha1().Releases(ns.Name).Update(&r)
			if err != nil {
				panic(err)
			}
			delete(newRelease.Annotations, recoverConfigClaimKey)
			_, err = client.ReleaseV1alpha1().Releases(ns.Name).Update(newRelease)
			if err != nil {
				panic(err)
			}
		}
	}
}
func listSecret(client *kubernetes.Clientset, nss []corev1.Namespace) {
	for _, ns := range nss {
		ss, err := client.CoreV1().Secrets(ns.Name).List(metav1.ListOptions{})
		if err != nil {
			panic(err)
		}
		for _, s := range ss.Items {
			fmt.Printf("[bug] secret name %s\n", s.Name)
			exist := false
			for k, v := range s.Data {
				if strings.Contains(k, "cert") || strings.Contains(k, "crt") {
					cert, err := parseTLSCert(v)
					if err != nil {
						fmt.Printf("[Warning] kube-system:[%s] secret:[%s] key:[%v] err:[%v] v:[%v]\n", ns.Name, s.Name, k, err, string(v))
						continue
					}
					exist = true
					expired := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24
					minAge := day
					if expired < minAge {
						fmt.Printf("kube-system: %s %s key: %v time: %v \n", ns.Name, s.Name, k, expired)
					}
				}
			}
			if !exist {
				fmt.Printf("[Warning] notexist :%s %s\n", ns.Name, s.Name)
			}
		}
	}
}

func generatorClient(configPath string) *kubernetes.Clientset {
	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		panic(err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	return client
}

func parseTLSCert(cert []byte) (*x509.Certificate, error) {
	certDERBlock, _ := pem.Decode(cert)
	if certDERBlock == nil {
		return nil, fmt.Errorf("pem decode failed")
	}
	x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}
