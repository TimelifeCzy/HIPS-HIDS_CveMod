# Windows-Driver-Rootkit-LearningTools
v1.0功能：
1. minfilter管理：它允许自定义规则标记进程允许访问的目录/文件属性(r-w-x-off/on);
2. wfp管理：提供了基础的tcp/udp过滤规则
3. 内核注入技术：LDR；APC；
4. dll进程监控：COM；RPC;
5. 系统任务管理器：进程/线程/回调/模块，SSDT/IDT/FSD/DISK（只具备检测功能）

v2.0功能：
实现轻量级和重定向概念
1. minfilter管理：添加文件操作重定向
2. wfp管理：提供DNS/FTP/HTTP监控与过滤
3. dll进程监控：文件/进程/线程/注册表监控
4. 提供SSDT/IDT基础修复功能。
