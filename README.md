# WIndows ProtonVPN For Windows Local Privilege Escalation Vulnerability

[TOC]



## 분석환경
### OS
- Windows 11 Pro x64 22h2 
- ProtonVPN For Windows v3.2.9

### Target
- ProtonVPNService.exe
  - version: v3.2.9
  - C:\Program Files\Proton\VPN\v3.2.9\ProtonVPNService.exe
    - Last Update: 2024.01.18


## 취약점 평가
- CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H 
- Attack Vector (AV): Local
- Attack Complexity (AC): Low
- Privileges Required (PR): Low
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): High
- Integrity (I): High
- Availability (A): High
- Base Score: 7.8 HIGH

## ProtonVPNService 분석

## ProtonVPN Service
- ProtonVPNService.exe(x64) 은 "ProtonVPN Service" 로 등록되어 있으며, user process 와 통신하는 프로세스.

  ![service properties](.\asset\service_permi.png)

또한, 해당 서비스는 위 사진과 같이 user 권한으로 시작, 중지가 가능함.

## 취약점1.  Arbitrary Folder Deletion TO Arbitrary File Move

ProtonVPNService.exe 서비스 process는 실행 될 때, target 폴더를 삭제하는 취약점이 있음.

- target folder: C:\Users\\**<user>**\AppData\Local\ProtonVPN\Updates

![vuln 1](.\asset\v1_afd.png)

해당 취약점이 트리거되는 시점에 procmon 툴을 이용하여 ProtonVPNService.exe 프로세스의 콜스택을 아래에서 확인할 수 있다. 

```wiki
0	FLTMGR.SYS	FltGetStreamContext + 0x20cb	0xfffff80731b2961b	C:\Windows\System32\drivers\FLTMGR.SYS
1	FLTMGR.SYS	FltGetStreamContext + 0x1b51	0xfffff80731b290a1	C:\Windows\System32\drivers\FLTMGR.SYS
2	FLTMGR.SYS	FltGetStreamContext + 0xad9	0xfffff80731b28029	C:\Windows\System32\drivers\FLTMGR.SYS
3	FLTMGR.SYS	FltGetStreamContext + 0x8bb	0xfffff80731b27e0b	C:\Windows\System32\drivers\FLTMGR.SYS
4	ntoskrnl.exe	IofCallDriver + 0x55	0xfffff807304ebef5	C:\Windows\system32\ntoskrnl.exe
5	ntoskrnl.exe	NtSetInformationFile + 0xdc4	0xfffff807304b2cb4	C:\Windows\system32\ntoskrnl.exe
6	ntoskrnl.exe	NtSetInformationFile + 0x3c3	0xfffff807304b22b3	C:\Windows\system32\ntoskrnl.exe
7	ntoskrnl.exe	setjmpex + 0x8df5	0xfffff8073062bbe5	C:\Windows\system32\ntoskrnl.exe
8	ntdll.dll	ZwSetInformationFile + 0x14	0x7ff8a59cf854	C:\Windows\System32\ntdll.dll
9	KernelBase.dll	RemoveDirectoryW + 0x1c9	0x7ff8a2edf3b9	C:\Windows\System32\KernelBase.dll
10	KernelBase.dll	RemoveDirectoryW + 0x17	0x7ff8a2edf207	C:\Windows\System32\KernelBase.dll
11	System.Private.CoreLib.dll	System.Private.CoreLib.dll + 0x1ab5bd	0x7ff827f5b5bd	C:\Program Files\Proton\VPN\v3.2.9\System.Private.CoreLib.dll
12	System.Private.CoreLib.dll	System.Private.CoreLib.dll + 0x39aca2	0x7ff82814aca2	C:\Program Files\Proton\VPN\v3.2.9\System.Private.CoreLib.dll
13	System.Private.CoreLib.dll	System.Private.CoreLib.dll + 0x39abe6	0x7ff82814abe6	C:\Program Files\Proton\VPN\v3.2.9\System.Private.CoreLib.dll
14	System.Private.CoreLib.dll	System.Private.CoreLib.dll + 0x39a65e	0x7ff82814a65e	C:\Program Files\Proton\VPN\v3.2.9\System.Private.CoreLib.dll
15	System.Private.CoreLib.dll	System.Private.CoreLib.dll + 0x38f02a	0x7ff82813f02a	C:\Program Files\Proton\VPN\v3.2.9\System.Private.CoreLib.dll
16	<unknown>	0x7ff7cae0ad67	0x7ff7cae0ad67	
```

-  해당 취약점은 RemoveDirectoryW 함수에 로컬 공격자가 수정가능한 위치의 폴더를 지우는 행위를 악용하여 공격자는 원하는 위치에 원하는 파일을 배치 할 수 있습니다.

### **임의의 폴더 삭제에서 로컬 권한 상승까지 🔥**

폴더을 SYSTEM EoP(관리자 권한 상승)으로 삭제하는 경우, 취약한 SYSTEM 프로세스가 임의의 폴더나 파일을 지정하는 것을 허용하지 않더라도 임의의 폴더의 내용을 삭제하거나 공격자가 쓸 수 있는 폴더에서 파일을 재귀적으로 삭제하는 것이 가능한 경우(RemoveDirectoryW  EoP가 가능 해지고 원하는 폴더를 삭제할 수 있습니다. 해당 과정은 다음과 같습니다.

- folder1: 취약한 폴더, target folder

1. temp\folder1이라는 하위 폴더를 생성합니다.
2. temp\folder1\file1.txt이라는 파일을 생성합니다.
3. temp\folder1\file1.txt에 oplock을 설정합니다.
4. 취약한 프로세스가 temp\folder1의 내용을 열거하고 거기에서 발견한 파일 file1.txt을 삭제하려고 시도할 때까지 기다립니다. 이렇게 하면 oplock이 트리거됩니다.
5. oplock이 트리거되면 콜백에서 다음을 수행합니다:
   a. file1.txt를 다른 위치로 이동하여 temp\folder1이 비어 있고 삭제할 수 있도록 합니다. file1.txt를 삭제하는 대신 이동시키는 이유는 삭제하려면 먼저 oplock을 해제해야 하기 때문입니다. 이 방법으로 우리는 oplock을 유지하여 취약한 프로세스가 계속 기다리도록 하면서 다음 단계를 수행할 수 있습니다.
   b. temp\folder1을 '객체 네임스페이스의 \RPC Control 폴더로의 심볼릭 링크인 ' junction으로 다시 생성합니다.
   c. 새로운 심볼릭 링크를 생성하여 '\RPC Control\file1.txt'를 'C:\Config.Msi::$INDEX_ALLOCATION'을 가리키도록 합니다.
6. 콜백이 완료되면 oplock이 해제되고 취약한 프로세스가 계속 실행됩니다. file1.txt의 삭제는 C:\Config.Msi의 삭제로 변합니다.

---

   이때, 바로 C:\Config.Msi를 삭제하지 않은 이유는 위 과정으 거치지 않으면, ProtonVPNService.exe에서 심볼릭 링크 파일을 추적한 위치를 삭제하지 않고 링크 파일 자체를 삭제하기 때문에, 혼선을 주기 위한 트릭임.

이제,  C:\Config.Msi 폴더를 삭제 할 수 있기 때문에 다음과 같은 과정을 따르면, 원하는 위치에 원하는 파일을 배치 할 수 있음.

1. Windows Installer 서비스는 응용 프로그램 설치를 수행하는 데 책임이 있으며, 설치가 완료되지 못한 경우 롤백 정보를 저장하기 위해 C:\Config.Msi 폴더를 생성하고 롤백 파일 (.rbf) 및 스크립트 (.rbs)로 채웁니다.
2. 공격자가 임의의 폴더 삭제 취약점을 가지고 있다면, Windows Installer가 이를 생성한 직후에 C:\Config.Msi를 제거하고, 약한 DACL(사용자가 C:\에 폴더를 생성할 수 있도록 권한 부여)을 가진 것으로 다시 만들 수 있습니다.
3. 이제 Windows Installer가 C:\Config.Msi 내에 롤백 스크립트를 생성하면, 권한이 없는 사용자는 그 중 하나를 악성 .rbs 스크립트로 대체할 수 있습니다. 이는 롤백 시 트리거될 때 악성 DLL을 드롭합니다.
4. 악성 .rbs 스크립트가 C:\Program Files\Proton\VPN\v3.2.9 폴더에 악성 profapi.dll(을 드롭하면, 권한이 없는 사용자는 ProtonVPNService.exe 서비스 프로세스를 시작하고 공격자의 코드를 로딩하여 SYSTEM 명령 프롬프트를 얻을 수 있습니다.



## 취약점2.  ProtonVPN Service DLL Side Loading

공격자는 취약점 1을 통해서 원하는 위치에 원하는 파일을 배치 할 수 있기 때문에, ProtonVPNService.exe 파일이 있는 폴더에 DLL Side Loading 취약점을 이용하여 system process로 코드를 로딩 할 수 있음.

해당 취약점은 ProtonVPNService.exe 파일과 동일 폴더에 profapi.dll(x64)이란 이름으로 파일을 배치하면,  공격자가 원하는 코드가 로딩됨.

- target path: C:\Program Files\Proton\VPN\v3.2.9\profapi.dll

![vuln 2](.\asset\v2_dllside.png)



## Exploit Flow

### Flow chart

![vuln 2](.\asset\fc.png)

1. C:\Config.Msi 폴더를 지정하고 있는 trick.txt 심볼릭 링크 파일을 `Updates`폴더 안에 생성( **Folder Contents Delete**).
2. 취약점 1을 트리거 시켜, Updates 폴더를  RemoveDirectoryW 함수로 트리거되면,, 실제 trick.txt 지정되고 합번더 링크를 따라거면 C:\Config.Msi 폴더를 가르키고 있음.(ABUSING, PATH REPARSE를 유도함.)
3.  Windows Installer를 rollback 기능을 이용하여 C:\Config.Msi 폴더가 삭제되는 시점에 롤백 파일 (.rbf) 및 스크립트 (.rbs)를 바꿔치기 하여, 공격자는 원하는 위치에 원하는 파일을 배치함.(Arbitrary File Delete to Arbitrary File Create EoP)
4. ProtonVPN Service DLL Side Loading 취약점을 이용하여 서비스 프로세스에 원하는 코드를 로딩함.

## Build

1. SystemCmdLauncher 프로젝트에 dllmain.cpp, DoIt 함수에 원하는 코드 작성 후 빌드함.
2. 바로 FolderOrFileDeleteToSystem 프로젝트 빌드함.(별도의 빌드 된 dll 파일 이동 필요없음.




## POC


<video src=".\asset\poc.mp4"></video>



## Limitation

- race condition으로 인해 이 공격으로 컴퓨터 자원이 부족할 경우 익스플로잇이 안될 수 있습니다.
  - cpu 4개의 프로세서가 권장됩니다. 


- 비트는 대상 시스템와 일치해야 합니다.

  

## 참고 문서

- [ABUSING ARBITRARY FILE DELETES TO ESCALATE PRIVILEGE AND OTHER GREAT TRICKS](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)

- [FilesystemEoPs](https://github.com/thezdi/PoC/blob/master/FilesystemEoPs)
- [Wacom Driver Arbitrary File Deletion Vulnerability](https://lucabarile.github.io/Blog/CVE-2022-38604/index.html#par5https://lucabarile.github.io/Blog/CVE-2022-38604/index.html#par5)

끝.
