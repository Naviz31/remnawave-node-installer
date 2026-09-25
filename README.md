# 🌊 Remnawave Node Installer

## ⚡ Быстрый запуск

```bash
curl -fsSL https://raw.githubusercontent.com/Naviz31/remnawave-node-installer/v1.2.0/install.sh | sudo bash
```

Во время установки скрипт запросит IP панели, домен, TLS-профиль ноды и ключ `SECRET_KEY`. Для нескольких IP панели введите их через запятую. Для выхода нажмите `Ctrl+C`.

Безопасный установщик Remnawave Node для чистого Ubuntu/Debian VPS.

Установщик задаёт вопросы:

| Поле | Что вводится |
|---|---|
| 🖥️ IP панели | Один или несколько IPv4/IPv6 через запятую |
| 🌐 Домен | FQDN, например `node.example.com` |
| 🔀 TLS-профиль | Xray/Reality напрямую на `:443` или Nginx TLS + WebSocket |
| 🔐 Ключ ноды | Значение `SECRET_KEY`, скопированное из Remnawave Panel |

IP панели используется для ограничения доступа к API ноды в firewall. Установщик не открывает `NODE_PORT` для всего интернета и не пытается угадывать панель по TCP peer.

Ключ вводится обычной строкой и отображается на экране, поэтому после вставки из буфера обмена его значение видно сразу.

Bootstrap загружает исходный код не с плавающего `main`: внутри `install.sh` зафиксированы commit и SHA-256 архива. При выпуске новой версии обновляются обе контрольные величины.

Для автоматического запуска можно заранее задать `PANEL_IPS` и `TLS_MODE` в `/etc/remnawave-node/config.env` или передать переменные окружения. Чтобы использовать `nginx-ws`, добавьте `TLS_MODE=nginx-ws`; порт inbound можно переопределить через `WS_PROXY_PORT`.

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
Xray/Reality mode:                 Nginx TLS + WebSocket mode:
Internet :443                      Internet :443
      │                                   │
      ▼                                   ▼
Xray / Reality                     Nginx TLS termination
      │                              ┌────┴─────┐
      ▼                              │          │
/dev/shm/nginx.sock          WebSocket upgrade   ordinary HTTPS
      │                       127.0.0.1:10000          │
      ▼                                                  ▼
Nginx cover website                              Nginx cover website
```

| Компонент | Назначение |
|---|---|
| `remnanode` | контейнер `remnawave/node:3.4.1`, `network_mode: host` |
| `:2222` | API ноды; разрешён только для `PANEL_IPS` |
| `:80` | HTTP-01 challenge и статический сайт |
| `:443` | Xray/Reality в режиме `xray`; Nginx с TLS и WS proxy в режиме `nginx-ws` |
| `/dev/shm/nginx.sock` | локальный Nginx backend для Reality self-steal/fallback |
| `/opt/remnanode/.env` | ключ и порт, права `0600` |

### Важная граница ответственности

`Xray Config Profile` настраивается в Remnawave Panel. Установщик не создаёт и не изменяет Config Profile, inbound, outbound, routing, Reality или Xray-конфигурацию.

Для сценария Reality Self-Steal Config Profile должен направлять ordinary HTTPS/fallback на:

```text
/dev/shm/nginx.sock
```

Для профиля VLESS + WebSocket + TLS выберите режим `nginx-ws`. Nginx завершает TLS на `:443`, передаёт WebSocket-запросы в локальный порт inbound и оставляет обычный HTTPS на сайте-подложке. Путь WebSocket не зашит в конфигурацию Nginx: входящий URI проксируется без изменений. Настройте inbound в панели на `127.0.0.1:10000` с транспортом WS и без TLS, а в Host задайте TLS на `:443` и тот же WS-путь, что указан в inbound. При другом локальном порте задайте `WS_PROXY_PORT`.

Режим `xray` оставляет внешний `:443` Xray и подходит для прямого Reality/XTLS и self-steal. Эти режимы используют один публичный порт, поэтому выберите режим в соответствии с Config Profile до установки.

После установки нода может отображаться как работающая, а Xray — как ожидающий Config Profile. Это означает, что окружение готово, но профиль ещё не назначен в панели.

## 🔐 Firewall и SSH

- существующая UFW не сбрасывается и не заменяется;
- при активной UFW установщик не добавляет широкое правило SSH: существующие ограничения доступа к SSH сохраняются;
- native nftables выбирается только при наличии подходящей существующей `inet input` chain; Docker `iptables-nft` сам по себе не переключает установщик на nftables;
- при iptables создаются отдельные IPv4/IPv6 цепочки `REMNAWAVE_NODE` и `REMNAWAVE_NODE6`;
- iptables-jump матчится только на `NODE_PORT`, поэтому правила SSH/HTTP/HTTPS администратора не обходятся;
- `NODE_PORT` не открывается всему интернету;
- Self-Steal socket принимает PROXY protocol v1 (`xver: 1`) через `proxy_protocol`;
- Fail2ban получает отдельный jail для SSH и не перезаписывает чужие jail;
- опасные операции `iptables -F`, `nft flush ruleset` и `ufw reset` не используются.

Порт SSH автоматически не меняется, root-доступ и метод аутентификации не отключаются.

## 🧰 Команды

| Команда | Действие |
|---|---|
| `remnawave-node status` | короткий dashboard состояния |
| `remnawave-node doctor` | расширенная диагностика и рекомендации |
| `remnawave-node repair` | восстановление управляемых файлов и контейнера |
| `remnawave-node update` | выбор последнего стабильного semver-тега Docker Hub в текущей major-линейке, pull и rollback при ошибке |
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
| `PANEL_IPS` | запрашивается интерактивно | один или несколько IP панели через запятую; для автоматического запуска можно хранить в `/etc/remnawave-node/config.env` |
| `PANEL_IP` | пусто | совместимый короткий вариант для одного IP |
| `NODE_PORT` | `2222` | внутренний API-порт ноды; `61001` зарезервирован |
| `TLS_MODE` | выбор при установке (`xray` по Enter) | `xray` или `nginx-ws` |
| `WS_PROXY_PORT` | `10000` | локальный порт VLESS/WS inbound для `nginx-ws` |
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

Ресурс регистрируется в manifest сразу после создания, до следующей потенциально падающей команды. При rollback удаляются только пакеты, Docker и сертификат, созданные именно этой транзакцией; сервисы возвращаются к исходным состояниям. Существовавшие каталоги сайта, Nginx/hook-файлы и чужие firewall rules не удаляются.

`repair` также работает как транзакция: до изменения firewall сохраняется прежний план, а финальный health-check выполняется до commit. При сбое state получает recovery-статус, и повторный `repair` сначала пытается восстановить прежний firewall.

## 🌐 TLS и cover website

Сертификат Let's Encrypt выпускается через HTTP-01 на порту `80`, после проверки DNS. В режиме `xray` Nginx не занимает внешний `443`; в режиме `nginx-ws` Nginx слушает `:443`, завершает TLS, проксирует WebSocket upgrade в `127.0.0.1:WS_PROXY_PORT`, а обычные HTTPS-запросы отправляет на сайт-подложку.

Локальный сайт генерируется из файлов репозитория, без загрузки случайных шаблонов из интернета. Он содержит страницы `/`, `/about/`, `/status/`, `/contact/`, custom `404` и `robots.txt`.

## ✅ Требования

- Ubuntu любой версии;
- Debian любой версии;
- root-доступ и systemd;
- минимум 1 ГБ RAM, 1 CPU и 5 ГБ свободного места;
- DNS A-запись домена на VPS;
- свободные порты `80`, `443` и `2222`;
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

Полная проверка firewall, выпуска сертификата, подключения панели и получения Config Profile требует реального VPS с DNS и Remnawave Panel. В режиме `xray` команда `doctor` проверяет listener на `:443` и Self-Steal HTTPS. В режиме `nginx-ws` она проверяет TLS ingress, HTTPS cover и локальный порт WS inbound; после первого появления backend его последующее исчезновение становится ошибкой диагностики.

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
│   ├── nginx.py               # HTTP и Unix-socket backend
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
