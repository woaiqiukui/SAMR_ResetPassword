# SAMR_resetntlm
SAMR修改域内主机密码

在打nopac的时候碰到MAQ为0的情况，需要去手动重置机器用户的密码，本来是想做个MAQ为0情况下的一键利用，先整出这么个副产品

整体框架参考loong716大牛子的changentlm.py；https://github.com/SecureAuthCorp/impacket/pull/1097

核心的hSamrSetPasswordInternal4New也是直接用的impacket.impacket.dcerpc.v5.samr.hSamrSetPasswordInternal4New

脚本暂只支持明文修改密码，对修改权限及被修改的域用户是否存在会进行校验

### 权限不够<img width="901" alt="image" src="https://user-images.githubusercontent.com/49117752/155889329-e81aae89-b2a4-4b39-bb5e-efecfd07ddb2.png">


### 用户不存在
<img width="906" alt="image" src="https://user-images.githubusercontent.com/49117752/155850074-ed8ce44a-c74b-4bcd-8a7b-baaea78dc1d3.png">



### 改密成功
<img width="900" alt="image" src="https://user-images.githubusercontent.com/49117752/155850066-91bd7686-f4da-4e34-86a8-49b4282fcbe3.png">
