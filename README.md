# 🌊 Remnawave Node Installer

Безопасный установщик Remnawave Node для чистого Ubuntu/Debian VPS.

Установщик задаёт только два вопроса:

| Поле | Что вводится |
|---|---|
| 🌐 Домен | FQDN, например `node.example.com` |
| 🔐 Ключ ноды | Значение `SECRET_KEY`, скопированное из Remnawave Panel |

IP панели задаётся до запуска в серверном конфиге. Это намеренно: установщик не открывает `NODE_PORT` для первого подключения и не пытается угадывать панель по TCP peer.

## ⚡ Быстрый запуск

Сначала один раз укажите публичный исходящий IP панели:

```bash
sudo install -d -m 0755 /etc/remnawave-node
printf 'PANEL_IPS=203.0.113.10\n' | sudo tee /etc/remnawave-node/config.env >/dev/null
sudo chmod 0644 /etc/remnawave-node/config.env
curl -fsSL https://raw.githubusercontent.com/Naviz31/remnawave-node-installer/v1.0.9/install.sh | sudo bash
```

После этого установщик интерактивно запросит только домен и ключ ноды. Для нескольких адресов используйте запятую:

Ключ вводится обычной строкой и отображается на экране, поэтому после вставки из буфера обмена его значение видно сразу.

```bash
printf 'PANEL_IPS=203.0.113.10,2001:db8::10\n' | sudo tee /etc/remnawave-node/config.env >/dev/null
sudo remnawave-node repair
```

Bootstrap загружает исходный код не с плавающего `main`: внутри `install.sh` зафиксированы commit и SHA-256 архива. При выпуске новой версии обновляются обе контрольные величины.

Если не хотите сохранять конфиг, допустим одноразовый запуск одной командой: `curl -fsSL https://raw.githubusercontent.com/Naviz31/remnawave-node-installer/v1.0.9/install.sh | sudo env PANEL_IPS="203.0.113.10" bash`. Установщик всё равно спросит домен и ключ.

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
                         /dev/shm/nginx.sock
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
| `/dev/shm/nginx.sock` | локальный Nginx backend для self-steal/fallback |
| `/opt/remnanode/.env` | ключ и порт, права `0600` |

### Важная граница ответственности

`Xray Config Profile` настраивается в Remnawave Panel. Установщик не создаёт и не изменяет Config Profile, inbound, outbound, routing, Reality или Xray-конфигурацию.

Для сценария Reality Self-Steal Config Profile должен направлять ordinary HTTPS/fallback на:

```text
/dev/shm/nginx.sock
```

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
| `PANEL_IPS` | обязательно | один или несколько IP панели через запятую; лучше хранить в `/etc/remnawave-node/config.env` |
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

Ресурс регистрируется в manifest сразу после создания, до следующей потенциально падающей команды. При rollback удаляются только пакеты, Docker и сертификат, созданные именно этой транзакцией; сервисы возвращаются к исходным состояниям. Существовавшие каталоги сайта, Nginx/hook-файлы и чужие firewall rules не удаляются.

`repair` также работает как транзакция: до изменения firewall сохраняется прежний план, а финальный health-check выполняется до commit. При сбое state получает recovery-статус, и повторный `repair` сначала пытается восстановить прежний firewall.

## 🌐 TLS и cover website

Сертификат Let's Encrypt выпускается через HTTP-01 на порту `80`, после проверки DNS. Nginx не занимает внешний `443`.

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

Полная проверка firewall, выпуска сертификата, подключения панели и получения Config Profile требует реального VPS с DNS и Remnawave Panel. Если Xray уже слушает `:443`, команда `doctor` дополнительно делает реальный `curl https://домен/` и проверяет HTTP 200 с HTML, а не только наличие Unix socket. После первого успешного Xray/Self-Steal check состояние запоминается; последующее исчезновение `:443` становится ошибкой диагностики.

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
