---
name: cloud-attack-methods
description: 目标使用云服务/容器/K8s，或拿到云凭据(AK/SK/Token)、发现 SSRF 与元数据服务时调用——云元数据利用、STS/IAM 提权、对象存储、K8s 逃逸、CI/CD 凭据链。
tags:
  cwe: [CWE-918, CWE-522, CWE-269, CWE-284]
  attack: [T1552.005, T1078.004, T1611, T1195]
  class: [cloud, kubernetes, container, cicd, metadata]
---

# 云与容器攻击手法

## 云元数据（SSRF/命令执行后的第一站）

- AWS：`http://169.254.169.254/latest/meta-data/iam/security-credentials/`（IMDSv1）；
  IMDSv2 需 PUT 拿 token：`TOKEN=$(curl -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds:21600' http://169.254.169.254/latest/api/token)`；
- 阿里云：`http://100.100.100.200/latest/meta-data/`（含 ram/security-credentials）；
- 腾讯云：`http://metadata.tencentyun.com/latest/meta-data/`；
- GCP：`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`（需 `Metadata-Flavor: Google`）；
- Azure：`http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`（需 Metadata: true）；
- 拿到临时凭据立即核实权限（`aws sts get-caller-identity`），**只读验证**，不写不删。

## 云凭据滥用（授权范围内）

- AWS：`aws configure` 后 `aws sts get-caller-identity` → `aws iam list-users/list-attached-user-policies`；
  S3：`aws s3 ls`、`aws s3 cp s3://bucket/file -`（只读样本）；
- 阿里云：`aliyun sts GetCallerIdentity`、`aliyun oss ls`（用 ossutil）；
- 对象存储直连：bucket 域名 + 目录列举特征（`?prefix=&max-keys=10`）；未授权列举/下载属 L3；
- 元数据泄露的 AK/SK 要**全文写入 fact**（含所属账号/服务），并注明来源文件/接口。

## IAM / STS 提权常见路径

- `iam:PassRole` + `ec2:RunInstances`（需谨慎，可能创造成本）；
- `iam:CreatePolicyVersion` / `AttachUserPolicy` 自提权；
- 角色信任策略过宽（`Principal: *`）；
- OIDC 联邦信任误配（GitHub Actions → AWS，注意 subject 条件）。
> 云上写操作一律禁止；最多 `simulate-principal-policy` 验证权限面。

## Kubernetes / 容器

- 在 Pod 内先看：`/var/run/secrets/kubernetes.io/serviceaccount/token`、`env | grep -i kube`；
- 用 token 探权限：`kubectl --token=<t> --server=https://kubernetes.default.svc auth can-i --list`；
- 逃逸面：privileged 容器、`hostPath` 挂载、`hostPID/hostNetwork`、docker.sock 挂载
  （`/var/run/docker.sock` 可列出宿主容器）；
- 容器内常见凭据：环境变量、ConfigMap 挂载、镜像层历史（`docker history`）；
- 结论要带证据：能读到宿主文件/宿主进程列表/其他命名空间资源截图。

## CI/CD 与供应链

- Jenkins：`/script` 未授权、`/computer/(master)/script`、凭据绑定（credentials 页面）；
- GitLab：CI 变量泄露、`/api/v4/projects` 未授权、runner token；
- GitHub Actions：`pull_request_target` 注入、workflow 里的 secrets 引用；
- 依赖投毒：内部 npm/pypi 源、`.npmrc`/`pip.conf` 指向的内网源。

## 边界

- 云控制面不做任何写操作（不创建资源、不改策略、不删数据）；
- 对象存储只取最小样本证明可读；
- 生产集群的逃逸验证到「可读宿主文件」即止，不横向到其他租户。
