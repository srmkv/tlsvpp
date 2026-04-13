v28 fixed10

Исправлено штатное ручное отключение:
- во время disconnect dataplane больше не пытается post/poll в пустой base URL
- убраны ложные ошибки вида unsupported protocol scheme ""
- закрытие transport/runtime теперь идёт в правильном порядке:
  cancel -> wait goroutines -> revert runtime -> clear active session/base
- shutdown ошибки dataplane больше не логируются как рабочие ошибки
