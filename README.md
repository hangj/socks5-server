# socks5 server

## rfc
[SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928.html)  

[GSS-API Authentication Method for SOCKS Version 5](https://www.rfc-editor.org/rfc/rfc1961)  

[Username/Password Authentication for SOCKS V5](https://www.rfc-editor.org/rfc/rfc1929)  


# How to use

```sh
git clone https://github.com/hangj/socks5-server.git
cd socks5-server
cargo r --release
curl -x socks5://localhost:1080 https://ipinfo.io/ip
```

