<div align="center">

<img src="icon.svg" width="256" height="256" alt="dsh-mesh-node 图标">

# dsh-mesh-node

**让棱镜通过与本地任务相同的派发入口，在存放项目的设备上执行任务。**

[English](README.md) | 简体中文

</div>

## 接入棱镜

需要 Node.js 24.9 或更高版本、npm、Git，以及对五个私有插件仓库的 Git 读取权限。检出脚本把匹配的插件和启动文件放入本机的 `runtime/` 目录，后续安装、配置和运行命令均在该目录执行。公开使用指南可直接阅读。需要调用示例模型时，请先在 DSH 凭据存储中配置 DeepSeek 凭据，或设置环境变量 `DEEPSEEK_API_KEY`。[安装指南](https://prism.dsh-plug.in/zh/)

```sh
git clone https://github.com/dsh-plugins/dsh-prism.git
cd dsh-prism
node scripts/checkout.mjs
cd runtime
npm ci
npm run build
npm start
```

## 连接第二台设备

1. 在两台设备上安装棱镜，各自设置 `mesh.nodeId` 并使用独立的 DSH 数据目录。
2. 为每台设备生成 Ed25519 密钥，将公钥登记到可访问的 WSS 信令服务，并在每台设备的 `mesh.peers` 中配置对方的节点 ID 和公钥。
3. 在执行设备为协调设备的 `projects` 列出允许访问的本地项目 ID。执行设备负责登记真实项目目录、模型和权限。
4. 在两台设备上配置 `mesh.webrtc`，按网络条件填入 STUN 或 TURN 服务器，然后启动两个宿主。

打开协调设备的日常对话，提出与已共享项目有关的请求。在任务卡查看进度，在执行设备的 DSH 工作区查看会话历史。从旧 HTTP Mesh 升级时，两端需更换节点 URL、链路令牌和 `incoming` 配置。信令和节点配置见技术参考。

[棱镜使用指南](https://prism.dsh-plug.in/zh/) · [技术参考](docs/TECH.md)
