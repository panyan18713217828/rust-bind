# Rust-Bind

### 项目介绍
- - -
此项目旨在学习Rust语法，掌握dns协议。</br>


### 目标
- - -
项目目标是实现一个完整的dns解析服务器，能够通过http管理解析记录并持久化到数据库中</br>
目前解析记录是在main.rs中写死的



### 构建
- - -
```text
cargo build
```

### 验证
- - -
```text
dig @127.0.0.1 -p 5300 www.example.com A
dig @127.0.0.1 -p 5300 www.example.com  AAAA +tcp
```