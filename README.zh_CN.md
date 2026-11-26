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
2. 在协调设备的 `mesh.peers` 中登记执行设备的节点 ID、HTTPS 地址和用于保存连接令牌的环境变量名。
3. 在执行设备的 `mesh.incoming` 中登记协调设备，列出允许其派发的项目 ID。在两台设备上设置相同的连接令牌。
4. 在两端注册表中使用相同的项目 ID，并将项目分配给执行设备。在执行设备上登记真实本地目录，配置该节点的模型和项目权限，然后启动两个宿主。

打开协调设备的日常对话，提出与登记项目有关的请求。任务卡和只读记录会出现在同一对话中。技术参考中附有两端配套的配置示例。

[棱镜使用指南](https://prism.dsh-plug.in/zh/) · [技术参考](docs/TECH.md)
