# TLSCTRL Web (fixed)

Запуск:
```bash
cd public
python3 -m http.server 9090
```

Открыть:
- `http://127.0.0.1:9090`

В поле `API base URL` указать адрес admin API agent, например:
- `http://192.168.1.17:9080`

Клиент TLS подключается не к web и не к admin API.
Он подключается к **mTLS API agent**:
- `https://192.168.1.17:9443`

Этот адрес записывается в `metadata.json` внутри `bundle.zip`.
