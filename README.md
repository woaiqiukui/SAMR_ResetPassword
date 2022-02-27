# SAMR_resetntlm
SAMR修改域内主机密码

在打nopac的时候碰到MAQ为0的情况，需要去手动重置机器用户的密码，本来是想做个MAQ为0情况下的一键利用，先整出这么个副产品

整体框架参考loong716大牛子的changentlm.py；https://github.com/SecureAuthCorp/impacket/pull/1097

核心的hSamrSetPasswordInternal4New也是直接用的impacket.impacket.dcerpc.v5.samr.hSamrSetPasswordInternal4New

脚本暂只支持明文修改密码，对修改权限及被修改的域用户是否存在会进行校验

### 权限不够
<img width="889" alt="image" src="https://user-images.githubusercontent.com/49117752/155889401-35d25495-0b96-48f7-ac41-28d4f6c08acd.png">


### 用户不存在
<img width="918" alt="image" src="https://user-images.githubusercontent.com/49117752/155889378-cf3cd755-13ed-4c5b-9cd8-d3b9a2776ae8.png">


### 改密成功
<img width="891" alt="image" src="https://user-images.githubusercontent.com/49117752/155889418-4b9b814d-007c-4e0a-aab5-62dfa1cc0e90.png">
<img width="1020" alt="image" src="https://user-images.githubusercontent.com/49117752/155889430-91aabbaf-e36b-41bf-bfa4-3dc5ea7657be.png">
<img width="724" alt="image" src="https://user-images.githubusercontent.com/49117752/155889440-da28003a-0abe-4536-a49d-7d4833f7629a.png">
