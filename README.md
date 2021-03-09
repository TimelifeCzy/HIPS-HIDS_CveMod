#### 概述：

&emsp;&emsp;业余学习笔记，主防模块分享。

#### 本篇环境：

```c++
1. wdk 7600 or Up new wdk
2. vs2015/17/19
3. Windows Win7 x86 sp1 / x64
4. IE Version 10/11
```

#### 知识点：

###### 基础：

DriverCallback/InlineHook/Dulib(UI)/ALPC 

###### 安全： 

漏洞/样本分析

#### 假设/构造：

&emsp;&emsp;从0开始想对病毒/漏洞进行防御,抵御已知的恶意手法/CVE，做一个非常简单的防御系统，样本分析或者Poc分析必不可少。基础恶意代码可以从攻击手法和多点防御，基础漏洞可以从某点上下文关键变量，内存判断。

&emsp;&emsp;系统应用漏洞分析已经快忘了，也花了时间去学习/调试。看文章之前具备基础知识比如悬空指针造/GC概念/UAF等。

##### IE部署问题：

```c++
1. Ie8 部分CVE_js/vbs启动调试崩溃，解决方案更新至10/11。
2. 升级IE 11之前需要安装必备的补丁包，链接如下：
https://docs.microsoft.com/zh-cn/troubleshoot/browsers/prerequisite-updates-for-ie-11
3. 升级IE 11,F12 Debug空白,仿真报错，安装补丁IE11-Windows6.1-KB3008923-x86即可解决。
4. js支持友好，vbs支持不友好，仿真兼容改成5。如果vbs还是不友好，Poc中加入VB函数，Windbg可以下断识，做为单步来Windbg观察。
vbs/js有些可以不使用IE调试，能触发就行（触发和利用两个概念）。
```

&emsp;&emsp;优质文章防御思路可以快速上手，推荐银雁冰好文有条有理（文末附带防御思路）。当然你可以找关键点，不用调试过程，但是失去了学习的意义：
https://bbs.pediy.com/thread-228371.htm

##### 构造方案：

1) Driver Callback监控Process-Thread-Module-Reg，如IE漏洞进程启动或者加载oleaut32.dll时候触发注入，ALPC通知应用层注入Mon.dll。

2) r3_Inject_DLL注入IE进行Inlinehook，监控变量及内存否存在uaf。触发拦截通知ServerPort，UI决定动作放行/拦截。

![png1](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/png1.png)



#### 代码实现：

##### 基础框架：

![image-20210115141215393](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115141215393.png)

alpc工程是lib，Cvecheck（DLL）-CveServer（Server）都链接该Lib库通信。

###### ALPC:

通信流程如下(端口一对一模式)：

&emsp;&emsp;NtAlpcCreatePort创建AlpcPort，利用AlpcSendWaitR等待端口Port被请求接收包，多线程非预期有可能不是上线请求，需要判断自定义的功能号区分。

```
enum CommandofCodeID
{
	ALPC_DRIVER_DLL_INJECTENABLE = 1,
	ALPC_DRIVER_DLL_INJECTDISABLE,

	ALPC_DRIVER_CONNECTSERVER = 10,
	ALPC_DRIVER_CONNECTSERVER_RECV,
	ALPC_DLL_CONNECTSERVER,
	ALPC_DLL_CONNECTSERVER_RECV,
	ALPC_UNCONNECTSERVER,

	ALPC_DLL_MONITOR_CVE = 30,
	ALPC_DLL_INJECT_SUCCESS,
	ALPC_DLL_INJECT_FAILUER
};
```



&emsp;&emsp;客户端NtAlpcConnect，服务端AlpcSendWaitR接收到连接请求，用NtAlpcAccept关联MessageId关联，绑定客户端handle。

&emsp;&emsp;服务端绑定NtAlpcAccept同时，也会发送给客户端消息Msg，参数7不但关联MessageId，且可以返回一个数据包给客户端，客户端接收之后可以处理第一次的上线请求。

![image-20210115141642449](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115141642449.png)

&emsp;&emsp;客户端发送Server消息单纯PortHandle是不够的，发送至客户端pmRequest里面的MessageId字段标识客户端连接时候ID。
&emsp;&emsp;r3创建事件消息，句柄通过上线握手传递给驱动(客户端)，驱动拿到手进行对象获取。应用场景就驱动事件等待r3处理进入睡眠,处理完成后被唤醒继续执行。代码中给出了这种方式应用示例没有使用，注入成功理论传递至驱动在做判断/使用内核态事件。

&emsp;&emsp;目前ALPC端口是1对1，后续会更改成1对多。

###### Server:

ALPC服务端，分别处理DLL_Monitor消息和Driver_Monitor。

![image-20210115141911978](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115141911978.png)

负责注入DLL(注入器) --- 代码中直接用了Apc注入，不在传输至r3，因为这种方案会导致死锁。

![image-20210115142115005](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115142115005.png)

###### Driver  <--> Server: 

负责回调拦截相关进程/模块，监控触发注入操作。

![image-20210115142814972](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115142814972.png)

Driver会先初始化ALPC_PORT，发送ALPC_DRIVER_CONNECTSERVER告诉服务端请求连接。

![image-20210115142910717](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115142910717.png)

Server接收到Driver请求构造回复，用于第一次上线将R3初始化句柄传递至r0，后续没用这种方式。

![image-20210115143408508](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115143408508.png)

Driver连接成功后创建读线程，AlpcRecvServerMsgROUTINE负责阻塞接收服务端发来的MSG请求。

```
	PsCreateSystemThread(
		&g_Recvhandle,
		THREAD_ALL_ACCESS,
		NULL,
		NtCurrentProcess(),
		NULL,
		(PKSTART_ROUTINE)AlpcRecvServerMsgROUTINE,
		NULL);
```

![image-20210115143801916](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115143801916.png)

进行模块监控，回调内容针对CVE-2016-0189，过滤条件oleaut32.dll和iexplore.exe。

```
status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)PsLoadImageCallbacks);
```

````
if (NULL != wcsstr(FullImageName->Buffer, L"Windows\\System32\\oleaut32.dll"))
````

![image-20210115144631190](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115144631190.png)

&emsp;&emsp;如果是iexplore.exe进程且加载了oleaut32.dll(代码中是注册的模块回调，先监视ole加载，后判断iexplore进程)，触发注入之后ALPC发送r3开始注入，回调中KeWaitForSingleObject事件等待，等待注入完成再执行，真实测试中r3再跨进程内存申请会阻塞VirtualAllocEx(这种方案会造成死锁)，所以直接回调APC注入解决。

&emsp;&emsp;关于上述阻塞问题，iiq大佬一开始说不是同一个线程即可，一开始不太明白，后来Hei大佬给除了较为详细的回答：因为模块回调是从mapview内进入的，内部有上线程锁，然后你又在同一线程allocate，vad的分配映射不能嵌套。因为如果发生缺页，那么就属于同一线程的物理页面竞争，而负责这块的平衡集管理器是按线程策略调度物理页面的。

```
			//  Send MSG r3 Server to Process HookMsg 
			DIRVER_INJECT_DLL drinjectdll = { 0, };
			INT32 Pids = 0;
			drinjectdll.ImageBase = ImageInfo->ImageBase;
			drinjectdll.Pids = PsGetCurrentProcessId();
			drinjectdll.univermsg.ControlId = ALPC_DRIVER_DLL_INJECTENABLE;
			

			AlpcSendMsgtoInjectDll(&drinjectdll);

			//
			// Wait Inject Process
			//
			if (&g_kEvent)
			{
				// KeWaitForSingleObject(g_pInjectEvent, Executive, KernelMode, FALSE, NULL); // INFINITE 
				// Wait
				KeWaitForSingleObject(&g_kEvent, Executive, KernelMode, FALSE, NULL);
				DbgBreakPoint();
				KeClearEvent(&g_kEvent);
			}
			
			// APC注入
				KAPC* Apc;
				Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
				RtlSecureZeroMemory(Apc, sizeof(KAPC));

				KeInitializeApc(Apc, KeGetCurrentThread(), 0, (PKKERNEL_ROUTINE)APCInjectorRoutine, 0, 0, KernelMode, 0);
				KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
```

&emsp;&emsp;AlpcSendMsgtoInjectDll（ALPC_DRIVER_DLL_INJECTENABLE）负责告诉Server需要注入iexplore.exe，CrrentPid/oleaut32.dll.ImageBase传递r3。

&emsp;&emsp;Server接收ALPC_DRIVER_DLL_INJECTENABLE处理，首先将创建Map映射ImageBase，DLL被注入后直接可以使用ImageBase(因为我不知道再回调完成之前是否可以使用GetModuleHandle获取得到DLLBaseAddr)。

&emsp;&emsp;注入使用常规远程线程注入方式会出现问题，上述已经解释原因。Server创建Share共享内存，发送给Driver可以进行ALPC注入了。

![image-20210115145130376](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115145130376.png)

ALPC_DLL_INJECT/FAILUER调用号一开始是为了r3注入准备的，但现在功能只是激活回调中的等待事件。

```
			UNIVERMSG univermsg = { 0, };
			if (nStatus)
				univermsg.ControlId = ALPC_DLL_INJECT_SUCCESS;
			else
				univermsg.ControlId = ALPC_DLL_INJECT_FAILUER;
			AlpcSendtoClientMsg(*SendtoPort, &univermsg, msgid);
```

Driver读线程中接收到INJECT.MSG功能号，进行事件唤醒。

![image-20210115145357915](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115145357915.png)

事件唤醒完成之后，进行apc-DLL注入，如下所示：

![image-20210121163150471](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210121163150471.png)

基本第一阶段完成，第二阶段DLL-hook级检测。

###### DLL  <--> Server:

DLL负责InlineHook，监控相关内存变化漏洞规则验证，触发通知Server处理。

![image-20210115150208235](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115150208235.png)

DLL注入iexplore.exe成功之后，先要获取共享MAP中的ImageBase，其次初始ALPC Port。

![image-20210115150402583](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115150402583.png)

&emsp;&emsp;DLL-ALPC初始化完成后，下面就是CVE-2016-0819检测，可以弹窗阻塞iex进程，OD附加进行调试，主要调试hook代码及CVE检测代码。

![image-20210121160442609](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210121160442609.png)



```
NTSTATUS InitVariantChangeTypeExHook(
	PVOID oleauthandle
)
{
	// Get VariantChangeTypeEx Address Save Old Addr or Virtual Mem Copy Opecode to VirMemory
	PVOID VariantChangeTypeExaddr = GetProcAddress((HMODULE)oleauthandle, "VariantChangeTypeEx");

	do
	{
		// Check ArgAddr
		if ((0 >= !VariantChangeTypeExaddr) || (0 >= !VariantChangeTypeExHook_Callback))
			break;

		// inline Hook
		syscall_VariantChangeTypeEx = (FnVariantChangeTypeExHook)Dll_Hook(VariantChangeTypeExaddr, VariantChangeTypeExHook_Callback);

	} while (false);

	return 0;
}
```

&emsp;IDA反汇编拷贝前12个字用来Hook。申请内存tramp，拷贝前12byte，紧跟着jmp跳转至原函数地址+12，这样调用原函数时候，tramp就可以直接调用，从而绕过hook的前12byte(Sandboxie代码中有Hook分析函数，寻找合适的Hook点)：

![image-20210115150825200](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115150825200.png)

![img](file:///C:\Users\Administrator\AppData\Roaming\Tencent\Users\502740367\QQ\WinTemp\RichOle\O~WWD_6A3GT8[LMD4J[MID5.png)

![image-20210121195338663](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210121195338663.png)

Hook完成之后就是对关键点检测，银雁冰文章中给出了具体的检测方案，直接套用如下：

![image-20210115151456904](https://github.com/TimelifeCzy/HIPS-HIDS_CveMod/blob/master/image-20210115151456904.png)

&emsp;&emsp;如果是漏洞，事件等待，DLL发送ALPC_DLL_MONITOR_CVE告诉Server监视到漏洞，Server将通过匿名管道将PID-CVE数据发送至UI,UI等待用户操作。

```
	case ALPC_DLL_MONITOR_CVE:
	/*++
		通知UI需要处理命中事件，等待UI返回
	--*/
	{
		MONITORCVEINFO* MonCveInfo = (MONITORCVEINFO*)((BYTE*)lpMem + sizeof(PORT_MESSAGE));
		if (!pipobj)
			break;
		pipobj->PipSendMsg((wchar_t*)MonCveInfo, sizeof(MONITORCVEINFO));
		// pipobj->PipClose();
	}
```

第二阶段主要是注入和CVE监控。

###### UI   <--> Server: 

UI负责交互/用户决定（目前代码是不可用，因为想使用electron做界面）

&emsp;&emsp;UI匿名管道接到Server的数据，将数据提取/创建UI界面提示用户有CVE攻击。等待用户放行还是结束，等待30s，选择默认拦截。拦截的话，直接结束浏览器/不调用该Api都可以，还可以还原数据大小，如果允许激活事件继续执行即可。

```
	if (g_PipServerPortHandle)
	{
		do
		{
			// PeekNamePipe用来预览一个管道中的数据，用来判断管道中是否为空
			if (!PeekNamedPipe(g_PipServerPortHandle, NULL, NULL, &dwRead, &dwAvail, NULL) || dwAvail <= 0)
			{
				break;
			}
			if (ReadFile(g_PipServerPortHandle, Databuffer, BUFSIZE, &dwRead, NULL))
			{                                                       
				if (dwRead != 0)
				{
					// 直接提示处理
				}
			}
		} while (TRUE);
	}
	return 0;
```

#### 防御效果：



#### 后记：

&emsp;&emsp;框架实现起来相对简单，后续也会跟着好文学习分享，附件提供了源码和Win7 x32下可执行程序。
