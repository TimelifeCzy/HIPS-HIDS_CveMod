# HIPS-HIDS_CveMod

这套代码当前更适合作为一套 CVE 检测/拦截 PoC 框架，主链路是：

`AntsDrv` 驱动发现目标进程加载 `oleaut32.dll`
`->` 通过 `CveDriverPort` 向 `CveServer` 发送注入请求
`->` `CveServer` 准备共享内存并回包
`->` 驱动在目标线程里做 APC 注入，加载 `CveCheck.dll`
`->` `CveCheck.dll` 连接 `CveMonitorPort`，安装漏洞点 hook
`->` 命中后再通过 ALPC 报告给 `CveServer`

## 组件

- `AntsDrv/`
  - 内核驱动。
  - 负责镜像加载回调、驱动侧 ALPC 客户端、APC 注入。
- `CveServer/`
  - 用户态服务端。
  - 负责创建 `CveDriverPort` 和 `CveMonitorPort` 两个 ALPC 端口。
  - 负责注入前后的共享数据和命中事件中转。
- `CveCheck/`
  - 被注入到目标进程的 DLL。
  - 负责连接监控端口并安装具体漏洞检测 hook。
- `CveCheckUI/`
  - UI 展示层。
  - 当前依赖一套匹配版本的 `DuiLib`，不是检测主链路必需组件。
  - 页面资源由 `skin/cvemodule/*` 打包成 `cvemodule.zip` 后嵌入到 EXE 资源中，运行时不依赖外部 xml。
- `alpc/`
  - ALPC 辅助静态库，供用户态项目链接。

## 检测流程

以 `CVE-2016-0189` 为例：

1. `AntsDrv!PsLoadImageCallbacks` 监控目标进程模块加载。
2. 当目标进程加载 `oleaut32.dll` 后，驱动提取 `ImageBase`，经 `CveDriverPort` 发给 `CveServer`。
3. `CveServer` 按目标 `PID` 创建共享内存 `ShareImageBase_<pid>`，写入 `ImageBase` 后再向驱动回包，表示注入前置条件已就绪。
4. 驱动 APC 注入 `CveCheck.dll`。
5. `CveCheck.dll` 启动后按当前 `PID` 读取 `ShareImageBase_<pid>`，连接 `CveMonitorPort`，然后对 `VariantChangeTypeEx` 安装 inline hook。
6. hook 命中后，DLL 将命中信息通过 `CveMonitorPort` 发回 `CveServer`。

## ALPC 用法

当前设计里 ALPC 分成两条链：

- `CveDriverPort`
  - 服务端：`CveServer`
  - 客户端：`AntsDrv`
  - 用途：驱动请求注入、服务端回注入状态
- `CveMonitorPort`
  - 服务端：`CveServer`
  - 客户端：`CveCheck.dll`
  - 用途：目标进程内检测命中上报

当前用法在“单驱动客户端 + 单目标调试链路”下是成立的，主逻辑是闭环的：

- 驱动先连接服务端，再发送注入请求。
- DLL 注入成功后再连接监控端口。
- 检测命中后，DLL 再把命中事件回传给服务端。

但要注意两个边界：

- `CveDriverPort` 现在天然就是单客户端模型，这个是合理的，因为只有一个驱动实例。
- `CveMonitorPort` 当前实现也是单连接串行处理，更适合单目标/单进程调试；如果未来要支持多个被注入进程同时上报，需要把服务端改成多连接 accept + worker 模型。

## 代码入口

- 驱动入口：`AntsDrv/AntsDrv.c`
  - `DriverEntry`
  - `PsLoadImageCallbacks`
- 驱动侧 ALPC：`AntsDrv/HlprDriverAlpc.c`
  - `AlpcDriverStart`
  - `AlpcSendMsgtoInjectDll`
- 服务端入口：`CveServer/CveServerMain.cpp`
  - `main`
- 服务端 ALPC：`CveServer/HlprServerAlpc.cpp`
  - `AlpcPortStart`
  - `DispatchMsgHandle`
- 注入 DLL 入口：`CveCheck/dllmain.cpp`
  - `InitMonitorThread`
- 漏洞检测实现：`CveCheck/Cve_2016_0189.cpp`
  - `VariantChangeTypeExHook_Callback`

## 编译说明

- 推荐环境：VS2019
