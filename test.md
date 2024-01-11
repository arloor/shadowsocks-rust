```
cargo run --package shadowsocks-rust --bin sslocal  -- --local-addr 0.0.0.0:2080 -k arloor.com  -v -m aes-256-gcm -s proxy.moontell.cn:8443 --protocol http
```


```bash
curl https://baidu.com -x http://localhost:2080
```
