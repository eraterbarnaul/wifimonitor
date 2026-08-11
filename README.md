# Wifimonitor

**Wifimonitor 2.0** — инструмент для авторизованного аудита Wi‑Fi: десктопное приложение на PyQt5 плюс headless‑режим и REST API. Пассивный мониторинг точек доступа и клиентов, захват WPA/WPA2/WPA3 handshakes и PMKID, оценка «атакуемости» сетей, набор активных атак, GPS‑wardriving и экспорт результатов (Excel/CSV/HTML/Hashcat).

> Только для тестирования собственных сетей и авторизованного пентеста. Запуск требует прав `root`/`sudo`.

## Возможности

**Сбор и анализ**
- обнаружение точек доступа и клиентов (BSSID, ESSID, канал, шифрование, RSSI, ширина канала, поколение Wi‑Fi 4/5/6/6E/7);
- парсинг RSN/WPA, HT/VHT/HE/EHT (802.11n/ac/ax/be) без внешних зависимостей;
- оценка атакуемости каждой сети (шифрование, WPS, 802.11w/MFP, PMKID, наличие клиентов) + производитель по OUI;
- сбор probe requests (PNL клиентов) и флаг рандомизированного MAC; раскрытие скрытых SSID;
- автопереключение по каналам (2.4/5/6 ГГц).

**Атаки (авторизованные)**
- деаутентификация (двунаправленная), выбор клиента или всех клиентов точки;
- перехват PMKID (clientless) и полного 4‑way handshake с валидацией качества (crackable/partial);
- активный запрос PMKID (association request) — не дожидаясь клиента;
- WPS‑атака через `reaver`/`bully` (разбор PIN/PSK);
- авто‑захват в один клик: lock канала → deauth → перехват → авто‑экспорт в hashcat 22000;
- взлом пойманного handshake по словарю через `aircrack-ng` (прогресс + вывод пароля).

**Blue‑team**
- пассивный детект deauth‑флуда и возможного evil‑twin с оповещениями.

**Локатор**
- живой график RSSI (~4 обновления/с), тренд «теплее/холоднее» с числовой Δ дБ, режим фиксации канала цели для плотных замеров.

**Экспорт и отчёты**
- нативный экспорт в Hashcat `*.hc22000` (EAPOL + PMKID, `hcxpcapngtool` не требуется);
- `*.xlsx`, `*.csv` (с защитой от CSV‑инъекций), HTML‑отчёт для пентеста.

**Wardriving и удалённое управление**
- GPS‑геометки точек через `gpsd` (таблица `ap_locations`);
- REST API + веб‑интерфейс для удалённого управления (headless/Raspberry Pi);
- headless CLI для автономных обходов; система плагинов атак; шина событий и слой use‑cases, общие для GUI/CLI/API.

## Архитектура
Логика отделена от Qt: слой `usecases.py` используют и GUI‑контроллер, и CLI, и REST API.

| Слой | Модули |
|---|---|
| Сбор/радио | `capture.py`, `deauth.py`, `pmkid_request.py`, `interface.py` |
| Разбор/анализ | `wifi_ie.py`, `audit.py`, `oui.py`, `detect.py`, `hashcat.py` |
| Атаки | `wps_attack.py`, `crack.py`, `auto_attack.py`, `plugins.py` |
| Данные/экспорт | `database.py` (SQLite WAL), `models.py`, `exporters.py`, `csv_export.py`, `report.py` |
| Приложение | `usecases.py`, `controller.py` (Qt), `events.py`, `gps.py`, `rest_api.py`, `cli.py`, `app.py`, `ui/` |

## Установка
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip aircrack-ng iw
# опционально: reaver bully (WPS), hcxtools (внешний экспорт), gpsd (wardriving)

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Или готовый пакет:
```bash
sudo apt install ./wifimonitor_2.0.0_all.deb   # Debian/Kali, с зависимостями
# либо дистро-независимый self-extracting установщик:
sudo ./wifimonitor_2.0.0.run
```

## Запуск

**GUI:**
```bash
sudo ./.venv/bin/python -m wifimonitor.app   # или: sudo wifimonitor
```
При старте выберите SQLite‑базу и каталог для захватов.

**Headless (автономный обход):**
```bash
sudo ./.venv/bin/python -m wifimonitor.cli -i wlan0 \
    --duration 300 --handshakes 5 \
    --db survey.db --captures ./caps --report survey.html
```
`--no-monitor-setup` — если адаптер уже в мониторном режиме; `--secondary <iface>` — второй адаптер для инъекции.

**REST API + веб‑интерфейс:**
```bash
sudo ./.venv/bin/python -m wifimonitor.cli -i wlan0 --api        # 127.0.0.1:8080, без токена
# наружу, с токеном (обязательно перед 0.0.0.0):
export WIFIMONITOR_API_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
sudo -E ./.venv/bin/python -m wifimonitor.cli -i wlan0 --api --api-host 0.0.0.0 --api-token "$WIFIMONITOR_API_TOKEN"
# или через файл, чтобы токен не попадал в `ps`/историю shell:
sudo ./.venv/bin/python -m wifimonitor.cli -i wlan0 --api --api-host 0.0.0.0 --api-token-file /path/to/token.txt
```
Веб‑интерфейс — на `/` (загружается без токена; для запросов к API откройте `/?token=...` один раз — страница сохранит токен в `localStorage` и уберёт его из адресной строки, либо введите его в поле «Токен доступа» внизу страницы). Эндпоинты:

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/api/status` | статус захвата |
| GET | `/api/access_points`, `/api/stations`, `/api/handshakes` | данные |
| GET | `/api/interfaces`, `/api/sessions` | интерфейсы, сессии |
| GET | `/api/plugins` | список зарегистрированных плагинов атак |
| POST | `/api/start`, `/api/stop` | старт/стоп захвата |
| POST | `/api/deauth`, `/api/deauth/stop` | деаутентификация |
| POST | `/api/auto_attack`, `/api/auto_attack/stop` | авто‑захват |

Все `/api/*` эндпоинты (кроме самой страницы `/`) требуют токен, если он задан — либо заголовком `Authorization: Bearer <token>`, либо `?token=...` в query. По умолчанию API слушает только `127.0.0.1` и токен не требуется; при `--api-host 0.0.0.0` без токена в лог пишется предупреждение. Не выставляйте API в недоверенную сеть без токена — используйте SSH‑туннель, доверенный сегмент или токен.

### Рабочий процесс (GUI)
1. «Мониторинг»: выберите интерфейс, «Применить» → «Старт». Канал‑хоппер собирает точки и клиентов; колонка «Оценка» показывает приоритет атаки.
2. «Перехват»: выберите точку и (опц.) клиента, настройте deauth или запустите «Авто‑захват». Handshakes/PMKID попадают в таблицу с меткой качества.
3. «Локатор»: выберите цель, включите «Зафиксировать канал» и по индикатору «теплее/холоднее» найдите устройство физически.
4. Экспорт (Excel/CSV/HTML/Hashcat) и взлом по словарю — из нижней панели.

## Wardriving (GPS)
Запустите `gpsd` (например, `sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock`). Wifimonitor подключается к нему по протоколу JSON (порт 2947) и сохраняет геометки точек в таблицу `ap_locations`; при недоступности gpsd геолокация просто отключается.

## Хранилище
- SQLite в WAL‑режиме с батч‑записью и rate‑limit; таблицы: `access_points`, `stations`, `handshakes`, `sessions`, `session_snapshots`, `ap_locations`;
- pcap‑дампы — в выбранном каталоге; логи сессии дублируются в `~/.wifimonitor/wifimonitor.log` (ротация).

## Сборка пакетов
```bash
bash packaging/build_deb.sh 2.0.0   # -> dist/wifimonitor_2.0.0_all.deb
bash packaging/build_run.sh 2.0.0   # -> dist/wifimonitor_2.0.0.run
```
CI (`.github/workflows/ci.yml`) гоняет тесты на Python 3.10–3.12 и `ruff`. Релиз собирается автоматически по пушу тега `v*` (`release.yml`): sdist + wheel + `.deb` + `.run` публикуются в GitHub Release.

## Диагностика
- Нет интерфейса в списке — проверьте адаптеры: `iw dev`.
- Для deauth/инъекции нужен адаптер с поддержкой monitor mode и пакетной отправки.
- WPS‑атака требует `reaver`/`bully`; взлом по словарю — `aircrack-ng`.

## Безопасность и правовой статус
Приложение предназначено для исследования собственных сетей и авторизованного тестирования. Убедитесь, что у вас есть письменное разрешение на перехват, деаутентификацию и подбор, и запускайте программу только с правами `root`/`sudo` там, где это допускается. REST API не имеет аутентификации — не открывайте его в недоверенные сети. Автор и сопровождающие не несут ответственности за незаконное использование.
