# Windows-Driver-Rootkit-LearningTools
Windows技术学习起来不一定连贯，但是技术栈是连贯的，希望初学者能从项目中发现属于自己的知识，从应用/方案/技术实现等综合思考(参考Sandboxie)

v1.0功能：
1. minfilter管理：它允许自定义规则标记进程允许访问的目录/文件属性(r-w-x-off/on);(v2.0生效)
2. wfp管理：提供了基础的数据展示(使用Windows_Filtering_Platform_Sample适用于初学者)
3. 内核注入技术：LDR；APC；
4. dll进程监控：COM；RPC;
5. 系统任务管理器：进程/线程/回调/模块，SSDT/IDT/FSD/DISK(暂定)

v2.0功能：

VT-EPT监控，实现实现轻量级和重定向概念
1. minfilter管理：规则过滤生效，添加文件操作重定向。
2. wfp管理：提供基础过滤拦截。
3. dll进程监控：文件/进程/线程/注册表监控
4. 提供SSDT/IDT基础修复功能。

学习笔记请跳转看雪：https://bbs.pediy.com/user-home-819685.htm
