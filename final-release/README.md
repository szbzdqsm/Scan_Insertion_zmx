# 已选终测包对应的最终源码

此快照对应用户选定并报告已上传的5页技术报告终测包，不代表接口适配版重新取得12例正常通过。

- 完整86文件源码指纹：ed2a25ff26313c34b6c0262c5da1120b21b3127eb18a536cf9ddb15daefd316e
- 已有镜像：sha256:589d4dd9928b47e54d2980fc92344a3b9071c9e784077d54c753cad6a8b4f6ef（linux/amd64、10层）
- 官方固定基础：sha256:9db0736a60bba851a848e20792202fe21ece0ba87a56944abf0003dafc5301d9
- 镜像tar SHA256：4db2c6ea83b631be20f3c2ae3575fd6118d7917b6bad79e5fa403672a8c8c2d3
- 5页报告终测ZIP SHA256：dc9d3f819f44a15c709d3b4da979d865b886a652323f375d6e1871575a2631da
- 公共测试ZIP SHA256：e4b773dc7b02dfc9821a760609e3fdf959889b27aa0f94d142998791270e9b48

## 恢复与构建

`submission/`是完整冻结源码，不是开发工作树。按`evidence/CANDIDATE.json`核对86文件SHA256和权限。Git只保留可执行位，完整Linux权限以清单为准。

保留的`submission/Dockerfile`属于原86文件中的历史增量配方，不作为最终低层构建入口。使用`build-context/Dockerfile`及同目录apply_delta.py、metadata.json和delta.tar，从上述固定官方基础恢复累计依赖、文件覆盖、删除和入口；不要从历史候选继续叠层。请先对本地`scan-agent-fixed-official:9db0736a60bba851a848e20792202fe21ece0ba87a56944abf0003dafc5301d9`执行image inspect，确认完整基础ID一致，然后：

```bash
docker build --platform linux/amd64 --network=none --pull=false \
  -t eda2602a4:restored-ed2a25ff ./build-context
```

构建只在确需恢复时手工进行；新构建的镜像ID不应无条件假设等于原镜像，需核对实际内容/配置/保护目录。原始镜像tar保留在用户本地，不存GitHub。

入口严格等待输入根case_upload_marker；实际观察到就绪后开始业务预算。业务和审计逻辑沿用父b9，输出全部关闭后最后写.case_complete_marker；完成标志不是任务成功证明。凭据仅由运行环境注入，不在源码仓库、镜像或公开归档中。

## 实际验证边界

已完成离线入口检查7/7、镜像正式入口禁网检查10/10、镜像实际内容/权限/模块/保护目录及tar回载核验。以上是合成检查，不是正常12例成绩。适配源码正常运行0/12；父b9历史本地12/12和平台case6失败分别保留，不宣称入口适配解决了case6稳定性。模型/扫描/ECO/EQY业务逻辑未因重新包装改变。

`evidence/`保留已完成检查和包绑定的无凭据记录；旧绝对路径作为历史出处，恢复以此完整快照及本地镜像/固定基础为准。私密.env、含Key的公共ZIP、镜像、官方输入数据及大规模历史输出不进入本Git快照。
