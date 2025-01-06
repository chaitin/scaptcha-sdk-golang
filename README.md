## 百川验证码服务 SDK-Golang

### 环境准备

访问验证码服务，创建验证码场景并获取配置信息

[国内应用地址](https://rivers.chaitin.cn/?rc=KYWFRHCKNYWJ7VAZQZSDNJUOAUSXZ4XB&app_scope=scaptcha)

### 业务接入
[前端业务接入 demo](https://github.com/chaitin/scaptcha-sdk-golang/-/blob/main/demo.html)

替换 demo.html 中的 business-id 为验证码服务的场景 ID

[后端业务接入 demo](https://github.com/chaitin/scaptcha-sdk-golang/-/blob/main/cmd/demo/demo.go)

替换 demo.go 中的 publicKeyStr 为下载的证书

verifyJWTokenken 为前端校验通过后验证码服务接口返回的 token