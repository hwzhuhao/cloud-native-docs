# 深入浅出云原生kubeconfig工具akcess

## 1.介绍

akcess 是一个命令行应用程序，可用于与其他团队共享对 Kubernetes 集群的细粒度访问。对于集群管理员而言，可以根据业务团队的需求产生一个精细化权限控制的kubeconfig，而并非所有的团队都直接给cluster-admin角色。

## 2.安装部署

```shell
#1.二进制下载
export VERSION=0.0.3
wget https://github.com/viveksinghggits/akcess/releases/download/v${VERSION}/akcess_${VERSION}_Linux_x86_64.tar.gz

#2.解压
tar -zxvf akcess_0.0.3_Linux_x86_64.tar.gz

#3.将解压后的二进制移动至/usr/local/bin下
mv akcess /usr/local/bin

#4.校验二进制
akcess version
```

## 3.验证

```shell
[root@node1 k8s-csr]# akcess -h
Create kubeconfig file with specified fine-grained authorization

Usage:
  akcess [flags]
  akcess [command]

Available Commands:
  allow       Allow the access to the resources
  completion  Generate the autocompletion script for the specified shell
  delete      Delete the kubernetes resources that were made specific allow command
  help        Help about any command
  list        List the number of times we ran the allow command
  version     Print the version of akcess

Flags:
  -h, --help   help for akcess

Use "akcess [command] --help" for more information about a command.
```

akcess主要提供了allow，delete，list功能，其中allow命令主要用户的配置来生成kubeconfig，所以下面的验证主要是围绕allow命令。

```shell
[root@node1 k8s-csr]# akcess allow -h
Allow the access to the resources

Usage:
  akcess allow [flags]

Flags:
  -f, --for int32               Duration the access will be allowed for (in minutes), for example --for 10. Defaults to 1 day (default 86400)
  -h, --help                    help for allow
  -k, --kubeconfig string       Path to kubeconfig file
  -l, --labels stringArray      Labels of the resources the specified access should be allowed on. For example, if you want to allow access to see logs of a set of pods that have same labels, instead of specifying all those pods separately using --resource-name field we can just specify label that is common among those resources
  -n, --namespace string        Namespace of the resource (default "default")
  -r, --resource strings        Resources/subresource to allow access on
      --resource-name strings   Resource names to allow access on, they are not validated to be present on the cluster
  -v, --verb strings            Allowed verbs
```

1.生成只具有访问default命名空间下pod权限的kubeconfig文件

```shell
akcess allow -n default -r pod -v get,list > testconfig
```

2.使用生成的testconfig测试访问default命名空间下pod，结果正常

```shell
[root@node1 ~]# kubectl get pod --kubeconfig testconfig
NAME                              READY   STATUS    RESTARTS   AGE
details-v1-79f774bdb9-nwkqn       2/2     Running   0          29d
productpage-v1-6b746f74dc-5qgcx   2/2     Running   0          29d
ratings-v1-b6994bb9-fxc6f         2/2     Running   0          29d
reviews-v1-545db77b95-zk4xl       2/2     Running   0          29d
reviews-v2-7bf8c9648f-zcscv       2/2     Running   0          29d
reviews-v3-84779c7bbc-vctt4       2/2     Running   0          29d
```

3.使用生成的testconfig测试访问kube-system命名空间下的pod，提示无权限访问

```shell
[root@node1 ~]# kubectl get pod -n kube-system --kubeconfig testconfig
Error from server (Forbidden): pods is forbidden: User "akcess-62p7b" cannot list resource "pods" in API group "" in the namespace "kube-system"
```

4.使用生成的testconfig测试访问default命名空间下的其他资源，比如configmap，提示无权限访问

```shell
[root@node1 ~]# kubectl get cm --kubeconfig testconfig
Error from server (Forbidden): configmaps is forbidden: User "akcess-62p7b" cannot list resource "configmaps" in API group "" in the namespace "default"
```

5.执行allow之后，也可以通过list命令查询生成的记录

```shell
[root@node1 ~]# akcess list
- id: e472bacb-2a66-41eb-b738-8c2f316be492
  createdAt: 2022-04-06T11:34:03.743166998Z
  namespace: default
- id: 699f96d4-fd88-4500-9a92-7d96c005644e
  createdAt: 2022-04-06T11:34:31.404444352Z
  namespace: default
```

6.如果想回收权限信息，可以通过delete命令，会删除生成的role，rolebinding和csr信息，这样使用生成的kubeconfig文件也无法通过kube-apiserver的鉴权。

```shell
[root@node1 ~]# akcess delete -h
Delete the kubernetes resources that were made specific allow command

Usage:
  akcess delete [flags]

Flags:
  -h, --help        help for delete
  -i, --id string   Id for which the k8s resources should be deleted. Can be figured out from list command
[root@node1 ~]# akcess delete -i 699f96d4-fd88-4500-9a92-7d96c005644e
[root@node1 ~]# kubectl get pod --kubeconfig testconfig
Error from server (Forbidden): pods is forbidden: User "akcess-62p7b" cannot list resource "pods" in API group "" in the namespace "default"
```

## 4.原理分析

### 4.1 allow命令

#代码入口位于cmd/root.go文件中

```go
var allowCmd = &cobra.Command{
	Use:   "allow",
	Short: "Allow the access to the resources",
	RunE: func(cmd *cobra.Command, args []string) error {
		// initialise clients
		config, _, err := utils.Config(options.KubeConfigPath)
		if err != nil {
			return errors.Wrap(err, "Creating rest.config object")
		}
		// clients has k8s typed as well as dynamic client
        // 创建k8s client
		clients, err := kube.NewClient(config)
		if err != nil {
			return errors.Wrap(err, "Initialising KubeClient")
		}
		options.Clients = *clients

		// de duplicate the values in the flags
		err = deDuplicateValues(cmd, options)
		if err != nil {
			return errors.Wrap(err, "Deduplicating options and creating resource options from resources")
		}
		// 参数校验
		err = validateArguments(options)
		if err != nil {
			return err
		}
		// 生成uuid
		id := uuid.New()
		conf := store.NewAkcessConfig(id.String(), options.Namespace)

		// init store
        // 初始化store，用于存放allow之后的记录
		s, err := store.NewFileStore()
		if err != nil {
			return errors.Wrap(err, "initialising filestore")
		}

		// should we do this after things are done
		// run this in a go routine
        // 将生成的记录写入文件~/.akcess/config中
		if err := s.Write(conf); err != nil {
			return fmt.Errorf("writing config to the filestore, %s\n", err.Error())
		}

		if err = s.Close(); err != nil {
			return errors.Wrap(err, "closing the filestore")
		}
		// 核心逻辑，创建csr，role和rolebindings
		kubeConfig, err := allow.Access(options, id)
		if err != nil {
			return err
		}
		// 输出最终生成的kubeconfig至stdout
		_, err = fmt.Fprint(os.Stdout, string(kubeConfig))
		return err
	},
}
```

#allow.Access方法位于pkg/allow/allow.go文件中

```go
func Access(o *AllowOptions, id uuid.UUID) ([]byte, error) {
    // 指定证书中的用户名，以akcess-xx命名，xx长度为5位
	commonName := fmt.Sprintf("%s-%s", utils.Name, apirand.String(5))
	// 生成private key
	key, err := privateKey()
	if err != nil {
		return nil, errors.Wrap(err, "Getting private key")
	}
	// 生成csr请求信息
	csr, err := csrForPrivateKey(key, commonName)
	if err != nil {
		return nil, errors.Wrap(err, "Generating CSR for private key")
	}

	_, clientconfig, err := utils.Config(o.KubeConfigPath)
	if err != nil {
		return nil, errors.Wrap(err, "Creating rest.config object")
	}

	// validate if namespace is available
	if err := o.Clients.ValidateNamespace(o.Namespace); err != nil {
		return nil, errors.Wrapf(err, "namespace %s was not found", o.Namespace)
	}

	// csr object from csr bytes
    // 组装csr对象结构体信息
	csrObject := kube.CSRObject(csr, o.ValidFor, id)

	// create CSR Kubernetes object
    // 调用k8s接口创建csr对象
	c, err := o.Clients.CreateCSR(csrObject)
	if err != nil {
		return nil, errors.Wrap(err, "Creating CSR kubernetes object")
	}

	// approve CSR
    // 自动审批CSR
	csrObject.Status.Conditions = append(csrObject.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.CertificateApproved,
		Status:         v1.ConditionTrue,
		Reason:         "Certificate was approved by akcess",
		Message:        "Certificate was approved",
		LastUpdateTime: metav1.Time{Time: time.Now()},
	})

	// accept context from parent
	ctx := context.Background()
    // 审批CSR
	_, err = o.Clients.KubeClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, c.Name, csrObject, metav1.UpdateOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Approving CertificateSigningRequest")
	}

	// wait for certificate field to be generated in CSR's status.certificate field
    // 等待获取csr中status.Certificate数据，该部分就是签发的客户端证书信息
	err = wait.Poll(certificateWaitPollInternval, certificateWaitTimeout, func() (done bool, err error) {
		csr, err := o.Clients.KubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, c.Name, metav1.GetOptions{})
		if string(csr.Status.Certificate) != "" {
			return true, nil
		}

		return false, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "waiting for CSR certificate to be generated")
	}

	// create role and rolebinding
    // 根据传入的参数，组装生成role对象结构体信息
	r, err := RoleObject(o, id)
	if err != nil {
		return nil, errors.Wrap(err, "error getting role object")
	}
	// 创建k8s role对象
	roleObj, err := o.Clients.CreateRole(r)
	if err != nil {
		return nil, errors.Wrap(err, "creating role object")
	}

	// role binding
    // 组装生成rolebinding对象信息，然后调研k8s接口创建rolebinding对象
	rb := kube.RoleBindingObject(roleObj.Name, commonName, o.Namespace, id)
	_, err = o.Clients.CreateRoleBinding(rb)
	if err != nil {
		return nil, errors.Wrap(err, "Creating rolebinding object")
	}

	// get csr again, so that we can get the certificate from status
	csrOp, err := o.Clients.KubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, c.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Getting CSR to fetch status.Certificate")
	}

	// Generate KubeConfig file
    // 生成kubeconfig信息
	return outputKubeConfig(clientconfig, key, csrOp.Status.Certificate, commonName)
}
```

```go
func outputKubeConfig(config *clientcmdapi.Config, key *rsa.PrivateKey, cert []byte, username string) ([]byte, error) {
    // 从config中获取集群信息
	name, cluster, err := clusterDetails(config)
	if err != nil {
		return nil, errors.Wrap(err, "getting cluster details")
	}
	// 生成config对象，其中key，cert和username是由Access函数中生成的，主要用来填充User部分信息
	c := utils.KubeConfig{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: utils.Clusters{
			0: {
				Cluster: utils.Cluster{
					CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(cluster.CertificateAuthorityData)),
					Server:                   config.Clusters[name].Server,
				},
				Name: name,
			},
		},
		Contexts: utils.Contexts{
			0: {
				Context: utils.Context{
					Cluster: name,
					User:    username,
				},
				Name: "test-context",
			},
		},
		CurrentContext: "test-context",
		Users: utils.Users{
			0: {
				User: utils.User{
					ClientCertificateData: base64.StdEncoding.EncodeToString(cert),
					ClientKeyData:         base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
				},
				Name: username,
			},
		},
	}

	out, err := yaml.Marshal(c)
	if err != nil {
		return nil, errors.Wrap(err, "converting generated config to yaml")
	}

	return out, nil
}
```

### 4.2 list命令

#代码入口位于cmd/root.go文件中

```go
// akcess list, to get set of resources created, so that we can delete them later
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List the number of times we ran the allow command",
	Long: `list can be used to figure out how many times the allow command was run.
	Because for every run we are going to create respective CSR, Role and RoleBinding objects,
	this command can then be used to delete the respective CSR, RoleBinding and Role resources for specific request`,
	RunE: func(cmd *cobra.Command, args []string) error {
        // 获取本地配置文件路径，位于用户主目录下.akcess/config
		s, err := store.NewFileStore()
		if err != nil {
			return errors.Wrap(err, "Opening file store")
		}
		// 读取配置文件内容，并反序列化成配置对象
		configs, err := s.List()
		if err != nil {
			return err
		}
		// 序列化
		bytes, err := yaml.Marshal(configs)
		if err != nil {
			return errors.Wrap(err, "marshalling list response")
		}

		if err := s.Close(); err != nil {
			return errors.Wrap(err, "closing the filestore after list")
		}
        // 打印输出结果至终端
		_, err = fmt.Fprint(os.Stdout, string(bytes))
		return err
	},
}
```

### 4.3 delete命令

#代码入口位于cmd/root.go文件中

```shell
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete the kubernetes resources that were made specific allow command",
	RunE: func(cmd *cobra.Command, args []string) error {
		return kube.DeleteResources(delIdentifier, kubeConfigPathDel)
	},
}
```

#kube.DeleteResources核心逻辑位于pkg/kube/kube.go文件中

```shell
func DeleteResources(id, kubeConfigFlag string) error {
	// accept context from parent
	ctx := context.Background()
	// create kubernetes client
	config, _, err := utils.Config(kubeConfigFlag)
	if err != nil {
		return errors.Wrap(err, "Creating rest.config object")
	}

	client, err := utils.KubeClient(config)
	if err != nil {
		return errors.Wrap(err, "Creating kubernetes client")
	}

	// read the config file and get the namespace
	s, err := store.NewFileStore()
	if err != nil {
		return errors.Wrap(err, "Creating store instance")
	}
	// 从~/.akcess/config中读取信息，里面包含了id，namespace，创建时间信息
	list, err := s.List()
	if err != nil {
		return errors.Wrap(err, "Calling list from store")
	}
	if err := s.Close(); err != nil {
		return err
	}

	var namespace string
	// get the namespace for the requested ID
	for _, c := range list {
	  	// 和用户命令行传入的id一致  
		if c.Id == id {
			namespace = c.Namespace
		}
	}

	// what if the namespace is not found because of certain reason

	// we can use dynamic clients and have common utility to delete these resources
	// 获取csr信息
	csr, err := client.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, c := range csr.Items {
	    // 遍历所有获取的csr，如果其annotation中allow.akcess.id的值和用户的id相等，则删除该csr
		if val, ok := c.Annotations[utils.ResourceAnnotationKey]; ok {
			if val == id {
				// delete this CSR object
				if err = client.CertificatesV1().CertificateSigningRequests().Delete(ctx, c.Name, *&metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}
	}
	// 获取其id对应ns下的所有roles
	roles, err := client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, r := range roles.Items {
		// 遍历所有roles信息，如果其annotation中allow.akcess.id的值和用户的id相等，则删除该role
		if val, ok := r.Annotations[utils.ResourceAnnotationKey]; ok {
			if val == id {
				if err = client.RbacV1().Roles(namespace).Delete(ctx, r.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}
	}
	// // 获取其id对应ns下的所有rolebindings
	roleBindings, err := client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, rb := range roleBindings.Items {
	    // 遍历所有rolebindings信息，如果其annotation中allow.akcess.id的值和用户的id相等，则删除该rolebindings
		if val, ok := rb.Annotations[utils.ResourceAnnotationKey]; ok {
			if val == id {
				if err = client.RbacV1().RoleBindings(namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}
	}

	// delete the entry from the config file
	s, err = store.NewFileStore()
	if err != nil {
		return err
	}
	// 删除存储在~/.akcess/config文件中的条目信息
	if err := s.DeleteWithID(id); err != nil {
		return err
	}
	return s.Close()
}
```

## 5.总结

akcess是一个不错的kubeconfig生成工具，方便集群管理员根据业务人员的权限申请使用来自动生成具体精细化权限控制的kubeconfig文件，同时还支持设置kubeconfig信息的时效性。但是其不支持用户自定义user和group信息，user是自动生成的，而且生成的记录仅存在于操作的本地机器上，如果机器出现文件破坏或者丢失，那么只能通过遍历查询所有的role和rolebindings记录，通过其annotation中的key信息来确定是否由该工具生成。

## 6.参考

[1] https://github.com/viveksinghggits/akcess

