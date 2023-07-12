# open-platform
本代码主要实现了四个组件：Crypt、OAuth、RBAC、MTenant，每个组件的主要功能如下：
✓ Crypt：封装了几个常用的密码学是算法，例如Hash、AES、RSA等
✓ OAuth：如何利用oauth体系做面向商户的身份鉴别，而不是面向终端用户的身份鉴别
✓ RBAC：基于角色的权限控制，一种权限控制的标准设计方法
✓ MTenant：一种接入型多租户的组件设计方法，同时结合OAuth和RBAC做身份鉴别与权限控制

网络上类似Crypt、OAuth、RBAC、MTenant的实现其实有很多，但如果仔细看其源代码的话，每种实现都有自己的理解，在概念上并不统一。
本文则从理论模型出发，推导出对应的组件结构，然后进一步细化结构体定义，最后用Golang实现，通过这种方法保证了概念的统一。
<br>
<img src="https://pic2.zhimg.com/v2-0ab2dd63cb6320119274890338fe51b5_r.jpg" width="500"/>

