# Mesh 节点技术参考

完整应用使用五个私有插件仓库，需要已获全部读取权限的 Git 凭据。在公开仓库根目录执行 `node scripts/checkout.mjs` 后进入 `runtime/`，再从该目录运行 npm、配置和启动命令。官网和使用文档可公开访问。[棱镜官网](https://prism.dsh-plug.in/)

将「远程设备上的 DSH 实例」封装成标准的 DSH Subagent Provider。这样对 L1/L2 而言，派发任务到另一台机器和在本地拉起一个子智能体调用的是完全相同的工具接口。

## 节点配置

棱镜（Prism）的编排插件按节点注册标准 DSH Subagent Provider，名称为 `prism-<nodeId>`。每次派发返回工作节点实际创建或恢复的 DSH Session ID。连接通过 `POST /prism/mesh/v1` 复用 DSH Web 监听端口，控制端发起出站请求并接收执行端的工具调用。执行端无需回连控制端。

在控制端的 `mesh` 配置中列出可派发的节点。

```json
{
  "nodeId": "hub",
  "peers": [
    {"id": "worker", "url": "https://worker.example.org", "tokenEnv": "PRISM_WORKER_TOKEN"}
  ]
}
```

在工作节点配置允许接入的节点和项目，双方在各自的环境变量中设置该链路的同一个随机凭据。不同入站节点使用独立凭据。跨机使用 HTTPS，本机回环地址可使用 HTTP。将面向控制端的域名加入工作节点 DSH 的受信任主机配置。

```json
{
  "nodeId": "worker",
  "incoming": [
    {"id": "hub", "tokenEnv": "PRISM_WORKER_TOKEN", "projects": ["atlas"]}
  ]
}
```

两端注册相同的项目 ID 和工作节点 ID，工作节点的注册表解析本机物理路径并检查用户访问权限。模型 ID 和编排工具名按工作节点的分层配置解析。L2 可授予的执行权限保存在工作节点，L3 启动时核对直接父会话、用户、项目、物理路径以及工具权限。远程 L1 仅能绑定其接入配置与执行节点配置共同指定的默认项目。每个逻辑会话按调用节点隔离。

`stateDirectory` 可指定存放节点绑定和权限记录的目录，默认为 `$DSH_HOME/data/prism/mesh`。只读会话查询走同一条经身份验证的链路。
