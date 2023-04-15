# socks5 server

rfc: [https://www.rfc-editor.org/rfc/rfc1928.html](https://www.rfc-editor.org/rfc/rfc1928.html)  



# How to use

```sh
git clone https://github.com/hangj/socks5-server.git
cd socks5-server
cargo r --release
curl -x socks5://localhost:1080 https://ipinfo.io/ip
```

