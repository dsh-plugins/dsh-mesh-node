# Mesh 节点技术参考

Mesh 在互相确认过设备公钥的节点之间建立 WebRTC DataChannel。信令服务通过 WSS 转发连接协商消息。任务、项目索引、Room 消息和工具结果通过设备之间的加密数据通道传输。需要中继时，TURN 转发加密数据。

## 生成设备身份

在每台设备生成一份独立的 Ed25519 私钥，用下面的命令打印配套的公钥。示例中的 `device.pem` 只留在生成它的设备上。

```sh
openssl genpkey -algorithm Ed25519 -out device.pem
node -e "const fs=require('node:fs'); const crypto=require('node:crypto'); console.log(crypto.createPublicKey(fs.readFileSync('device.pem')).export({format:'der',type:'spki'}).toString('base64url'))"
```

将 PEM 私钥文本放入该设备配置的 `privateKeyEnv` 环境变量。将公钥登记到信令服务以及需要与该设备建立连接的对端。每个对端使用独立的节点 ID 和公钥。

## 启动信令服务

信令服务可部署在任意一台所有设备都能访问的机器上。准备 TLS 证书和私钥，把节点 ID 与公钥填入 `signaling.json`。证书文件路径以配置文件所在目录为基准。

```json
{
  "host": "0.0.0.0",
  "port": 8443,
  "certFile": "cert.pem",
  "keyFile": "key.pem",
  "nodes": {
    "hub": "<hub 公钥>",
    "worker": "<worker 公钥>"
  }
}
```

使用插件包提供的 `dsh-prism-mesh-signaling --config signaling.json` 启动服务。从源码构建后，也可运行 `node dist/signaling-cli.js --config signaling.json`。默认 WebSocket 路径为 `/prism/mesh/signaling/v2`，可用 `path` 自定义。

## 配置设备

在协调设备的 `mesh` 配置中填入执行设备的节点 ID 和公钥。

```json
{
  "nodeId": "hub",
  "webrtc": {
    "signalingUrl": "wss://signal.example.org:8443/prism/mesh/signaling/v2",
    "privateKeyEnv": "PRISM_HUB_PRIVATE_KEY"
  },
  "peers": [
    {"id": "worker", "publicKey": "<worker 公钥>"}
  ]
}
```

执行设备列出允许协调设备访问的本地项目。工作节点自己的工作区注册表保存项目真实路径、用户权限和工具权限。

```json
{
  "nodeId": "worker",
  "webrtc": {
    "signalingUrl": "wss://signal.example.org:8443/prism/mesh/signaling/v2",
    "privateKeyEnv": "PRISM_WORKER_PRIVATE_KEY",
    "iceServers": [
      {"urls": ["stun:turn.example.org:3478"]},
      {
        "urls": ["turn:turn.example.org:3478", "turns:turn.example.org:5349"],
        "username": "worker",
        "credentialEnv": "PRISM_WORKER_TURN_PASSWORD"
      }
    ]
  },
  "peers": [
    {"id": "hub", "publicKey": "<hub 公钥>", "projects": ["atlas"]}
  ]
}
```

根据各设备的网络条件配置 `iceServers`。默认优先尝试可用的直连路径。将 `iceTransportPolicy` 设为 `relay` 可要求经 TURN 中继，且必须配置可用的 TURN 凭据。信令服务使用私人 CA 时，可通过 `signalingCaFile` 指定 PEM CA 文件。启用 Room 设备间通信时，两台执行设备也需互相登记公钥。

## 执行与迁移

编排器按节点注册标准 DSH Subagent Provider，名称为 `prism-<nodeId>`。派发返回执行设备实际创建或恢复的 DSH Session ID。工作节点在启动轮次前检查对端项目许可、项目用户权限、父会话和委派上限。远程项目索引只返回共享且当前用户可见的项目元数据。协调端展示任务进度，完整会话历史保存在执行设备的 DSH 工作区。

默认状态目录为当前 DSH 配置档的 `data/dsh-prism/mesh`。可通过 `stateDirectory` 指定已有的独立状态目录。迁移旧 HTTP Mesh 时，两端需同时替换 `peers[].url`、`tokenEnv` 与 `incoming` 配置，再按照新配置互认节点公钥。
