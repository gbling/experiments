# helix-config

#### 介绍
基于Fedora-39使用helix-23.10配置C开发环境

#### 软件安装

安装clangd二进制文件在clang-tools-extra包中

`yum -y install clang clang-tools-extra`

安装helix

`yum -y install helix`

#### helix配置

详细配置参数见文档[https://docs.helix-editor.com/usage.html](https://docs.helix-editor.com/usage.html)

> tips language.toml配置模板文件可以在[https://github.com/helix-editor/helix](https://github.com/helix-editor/helix)仓库中找对应的版本直接修改使用

使用命令下载对应的grammer

> 可以在language.toml文件开头设置只拉取哪些语言`use-grammars = { only = [ "c", "cpp" ] }`

`hx --grammar fetch`

拉取完成之后执行编译

`hx --grammar build`

完成之后检查是否正常

`hx --health c`
