# 🌊 Remnawave Node Installer

Безопасный установщик Remnawave Node для чистого Ubuntu/Debian VPS.

Установщик задаёт только два вопроса:

| Поле | Что вводится |
|---|---|
| 🌐 Домен | FQDN, например `node.example.com` |
| 🔐 Ключ ноды | Значение `SECRET_KEY`, скопированное из Remnawave Panel |

Остальные параметры имеют безопасные значения по умолчанию и настраиваются через окружение или локальный конфигурационный файл.

## ⚡ Быстрый запуск

IP панели обычно определяется автоматически: после запуска `remnanode` установщик коротко отслеживает фактическое входящее TCP-соединение на `NODE_PORT`, запоминает peer IP и затем создаёт firewall-правило только для него.

Поэтому обычная установка запускается одной командой и не требует `PANEL_IPS`:

```bash
curl -fsSL https://raw.githubusercontent.com/Naviz31/remnawave-node-installer/main/install.sh | sudo bash
```

`PANEL_IPS` остаётся необязательным override для случаев, когда панель подключается через NAT/CDN, имеет несколько исходящих IP или ещё не успела подключиться во время окна обнаружения:

```bash
sudo install -d -m 0755 /etc/remnawave-node
printf 'PANEL_IPS=203.0.113.10\n' | sudo tee /etc/remnawave-node/config.env >/dev/null
sudo chmod 0644 /etc/remnawave-node/config.env
sudo remnawave-node repair
```

Если соединение панели не обнаружено, установщик не открывает `NODE_PORT` всему интернету: он завершает установку с закрытым портом и показывает эту команду для повторной настройки.

> ⚠️ Для выпуска сертификата A-запись домена должна указывать на публичный IPv4 этого VPS. Проверка DNS включена по умолчанию.

### Запуск с клонированного репозитория

```bash
git clone https://github.com/Naviz31/remnawave-node-installer.git
cd remnawave-node-installer
sudo bash install.sh
```

## 🧭 Что происходит во время установки

```text
Preflight → Snapshot → Dependencies → Docker → Node
    ↓
Firewall → SSH protection → Nginx → Cover website → TLS
    ↓
Logrotate → Health checks → install-state.json
```

Каждый этап выполняется с проверкой результата. При критической ошибке запускается rollback, который удаляет только ресурсы, записанные в manifest.

## 🏗 Архитектура

```text
                         INTERNET
                             │
                         TCP :443
                             ▼
                  Remnawave Node / Xray
                 Config Profile из панели
                      ┌──────┴──────┐
                      │             │
                proxy traffic   ordinary HTTPS
                                    │
                                    ▼
                         127.0.0.1:9443
                                    │
                                  Nginx
                           neutral cover site
```

| Компонент | Назначение |
|---|---|
| `remnanode` | контейнер `remnawave/node:3.4.1`, `network_mode: host` |
| `:2222` | API ноды; разрешён только для `PANEL_IPS` |
| `:80` | HTTP-01 challenge и статический сайт |
| `:443` | после Config Profile обслуживается Node/Xray |
| `127.0.0.1:9443` | локальный HTTPS backend для self-steal/fallback |
| `/opt/remnanode/.env` | ключ и порт, права `0600` |

### Важная граница ответственности

`Xray Config Profile` настраивается в Remnawave Panel. Установщик не создаёт и не изменяет Config Profile, inbound, outbound, routing, Reality или Xray-конфигурацию.

Для сценария Reality Self-Steal Config Profile должен направлять ordinary HTTPS/fallback на:

```text
127.0.0.1:9443
```

После установки нода может отображаться как работающая, а Xray — как ожидающий Config Profile. Это означает, что окружение готово, но профиль ещё не назначен в панели.

## 🔐 Firewall и SSH

- существующая UFW не сбрасывается и не заменяется;
- при nftables создаётся отдельная таблица `remnawave_node`;
- при iptables создаётся отдельная цепочка `REMNAWAVE_NODE`;
- `ESTABLISHED,RELATED` и текущий SSH-порт разрешаются до остальных правил;
- `9443` не открывается наружу и дополнительно слушает только localhost;
- `NODE_PORT` не открывается всему интернету;
- Fail2ban получает отдельный jail для SSH и не перезаписывает чужие jail;
- опасные операции `iptables -F`, `nft flush ruleset` и `ufw reset` не используются.

Порт SSH автоматически не меняется, root-доступ и метод аутентификации не отключаются.

## 🧰 Команды

| Команда | Действие |
|---|---|
| `remnawave-node status` | короткий dashboard состояния |
| `remnawave-node doctor` | расширенная диагностика и рекомендации |
| `remnawave-node repair` | восстановление управляемых файлов и контейнера |
| `remnawave-node update` | pull текущего зафиксированного образа и health check |
| `remnawave-node set-secret` | скрытая смена `SECRET_KEY` с возвратом при ошибке |
| `remnawave-node logs` | последние логи контейнера в режиме follow |
| `remnawave-node uninstall` | удаление только ресурсов из manifest |

Для удаления требуется явное подтверждение:

```bash
sudo remnawave-node uninstall
```

### Параметры окружения

| Переменная | По умолчанию | Назначение |
|---|---:|---|
| `PANEL_IPS` | авто | один или несколько IP панели через запятую; отключает автоопределение |
| `PANEL_IP` | пусто | совместимый короткий вариант для одного IP |
| `NODE_PORT` | `2222` | внутренний API-порт ноды; `61001` зарезервирован |
| `REMNAWAVE_NODE_FAIL_AT` | пусто | тестовая инъекция ошибки на этапе установки |

Ожидаемые этапы для `REMNAWAVE_NODE_FAIL_AT`: `dependencies`, `docker`, `node`, `firewall`, `ssh`, `nginx`, `tls`, `logs`, `health`.

Пример безопасной проверки rollback на тестовом VPS:

```bash
REMNAWAVE_NODE_FAIL_AT=nginx sudo -E bash install.sh
```

## 💾 Rollback и manifest

Состояние хранится в:

```text
/var/lib/remnawave-node/install-state.json
/var/lib/remnawave-node/backups/<timestamp>/
/var/log/remnawave-node/installer.log
```

В manifest не записывается значение ключа. В нём фиксируются:

- существовавшие до запуска Docker, Nginx, Fail2ban и Node;
- созданные пути и конфигурационные файлы;
- применённый firewall backend и собственные правила;
- backup изменённых файлов;
- созданные сертификаты и hook renewal;
- результаты health check.

При rollback существовавшие Docker/Nginx/Fail2ban, сертификаты и чужие firewall rules не удаляются.

## 🌐 TLS и cover website

Сертификат Let's Encrypt выпускается через HTTP-01 на порту `80`, после проверки DNS. Nginx не занимает внешний `443`.

Локальный сайт генерируется из файлов репозитория, без загрузки случайных шаблонов из интернета. Он содержит страницы `/`, `/about/`, `/status/`, `/contact/`, custom `404` и `robots.txt`.

## ✅ Требования

- Ubuntu 22.04 или 24.04;
- Debian 12 или 13;
- root-доступ и systemd;
- минимум 1 ГБ RAM, 1 CPU и 5 ГБ свободного места;
- DNS A-запись домена на VPS;
- свободные порты `80`, `443`, `2222` и `9443`;
- исходящий доступ в интернет.

Docker Engine и Compose plugin устанавливаются автоматически, если их нет. Уже установленный Docker переиспользуется.

## 🧪 Проверки в репозитории

Локальные тесты не требуют Linux, Docker или root:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q remnawave_node
bash -n install.sh
```

На Linux VPS дополнительно рекомендуется проверить:

```bash
sudo nginx -t
sudo certbot renew --dry-run
sudo docker compose -f /opt/remnanode/docker-compose.yml config --quiet
sudo remnawave-node doctor
```

Полная проверка firewall, выпуска сертификата, подключения панели и получения Config Profile требует реального VPS с DNS и Remnawave Panel.

## 📁 Структура

```text
remnawave-node-installer/
├── install.sh                 # bootstrap для локального запуска и curl | sudo bash
├── README.md
├── LICENSE
├── pyproject.toml
├── requirements.txt           # runtime без внешних Python-зависимостей
├── config/defaults.env
├── remnawave_node/
│   ├── cli.py                 # install/status/doctor/repair/update/...
│   ├── install.py             # транзакция и этапы установки
│   ├── preflight.py           # проверки до изменений
│   ├── state.py               # manifest, backup, rollback state
│   ├── compose.py             # docker-compose и закрытый .env
│   ├── firewall.py            # UFW/nftables/iptables без destructive reset
│   ├── nginx.py               # HTTP и localhost HTTPS backend
│   ├── website.py             # локальный нейтральный сайт
│   ├── certificates.py        # certbot и renewal hook
│   ├── ssh_guard.py            # Fail2ban SSH jail
│   ├── health.py
│   ├── security.py            # redaction и атомарная запись 0600
│   └── ui.py                  # компактный TUI
└── tests/
```

## ⚖️ Лицензия

MIT. Используйте на собственных серверах и перед запуском всегда проверяйте DNS, IP панели и список занятых портов.
