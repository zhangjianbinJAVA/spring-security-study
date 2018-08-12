### 参考文档
Spring Security源码分析一：Spring Security认证过程:   
http://niocoder.com/2018/01/02/Spring-Security%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90%E4%B8%80-Spring-Security%E8%AE%A4%E8%AF%81%E8%BF%87%E7%A8%8B/


### Spring Security认证流程,包含相关的核心认证类 

![](img/spring-security核心认证类.png)

#### 总结
UserDetailsService接口作为桥梁，是DaoAuthenticationProvier与特定用户信息来源进行解耦的地方， 
UserDetailsService由UserDetails和UserDetailsManager所构成；   
UserDetails和UserDetailsManager各司其责，一个是对基本用户信息进行封装，一个是对基本用户信息进行管理；   

特别注意，UserDetailsService、UserDetails以及UserDetailsManager都是可被用户自定义的扩展点，   
我们可以继承这些接口提供自己的读取用户来源和管理用户的方法，比如我们可以自己实现一个 与特定 ORM 框架，  
比如 Mybatis 或者 Hibernate，相关的UserDetailsService和UserDetailsManager；   

#### 用户认证流程时序图

![](./img/用户认证流程时序图.png)