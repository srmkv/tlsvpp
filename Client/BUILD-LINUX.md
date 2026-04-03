# Linux packaging

## Быстрая локальная установка
```bash
./packaging/linux/scripts/install-local.sh
```

## Сборка .deb
```bash
./packaging/linux/scripts/build-deb.sh 1.0.0
```

Готовый пакет появится в `dist/`.

### Почему установщик не должен ругаться на отсутствие лицензии
В комплект добавлены:
- `LICENSE`
- AppStream metadata `packaging/linux/io.srmkv.tlsclientnative.metainfo.xml`
  с `metadata_license` и `project_license`
- Debian copyright file формируется автоматически из `LICENSE`


Исправление: в install-local.sh и build-deb.sh поправлен путь к корню проекта.
