<div align="center">

<img src="icon.svg" width="256" height="256" alt="dsh-mesh-node icon">

# dsh-mesh-node

**Let Prism run a task on the device that has the project, using the same delegation controls as a local task.**

English | [简体中文](README.zh_CN.md)

</div>

## Set up Prism

Use Node.js 24.9 or later, npm, Git and credentials with read access to the five private plugin repositories. The checkout script places matching plugins and launcher files in a local `runtime/` directory. Run subsequent installation, configuration and launch commands there. The public guide is available without signing in. To use the example models, configure your DeepSeek credentials in DSH or set the `DEEPSEEK_API_KEY` environment variable. [Installation guide](https://prism.dsh-plug.in/)

```sh
git clone https://github.com/dsh-plugins/dsh-prism.git
cd dsh-prism
node scripts/checkout.mjs
cd runtime
npm ci
npm run build
npm start
```

## Connect a second device

1. Install Prism on both devices and give each its own `mesh.nodeId` and DSH data directory.
2. On the coordinating device, add the worker to `mesh.peers` with its node ID, HTTPS URL and the name of the environment variable holding the link token.
3. On the worker, add the coordinator to `mesh.incoming`. Set the same link token on both devices and list the project IDs the coordinator may request.
4. In both project registries, identify the project by the same ID and assign it to the worker node. Register the real local directory on the worker. Configure that node’s models and project permissions, then start both hosts.

Open the coordinator’s usual chat and ask about the registered project. Its task card and read-only record are available in the same conversation. The technical reference includes matching configuration examples for both nodes.

[Prism documentation](https://prism.dsh-plug.in/) · [Technical reference](docs/TECH.md)
