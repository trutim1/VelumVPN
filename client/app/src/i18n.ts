export type Language = 'ru' | 'en';
export type TranslationParams = Readonly<Record<string, string | number>>;
export const DEFAULT_LANGUAGE: Language = 'ru';
export const LANGUAGE_STORAGE_KEY = 'velum.language';

// Source-text keys make untranslated copy visible during development. Never pass
// profile names, addresses, key material or server responses as translation keys.
export const en = Object.freeze({
  'Если правила не читаются, можно явно сбросить список. VPN-профили и ключи останутся без изменений.': 'If rules cannot be read, you can explicitly reset the list. VPN profiles and keys will remain unchanged.',
  'Сбросить правила приложений': 'Reset application rules',
  'Сохранённый список приложений будет заменён пустым списком, режим приложений будет выключен.': 'The saved application list will be replaced by an empty list and application mode will be turned off.',
  'Подтвердить сброс': 'Confirm reset',
  'Правила приложений сброшены. VPN-профили не изменены.': 'Application rules reset. VPN profiles unchanged.',
  'Сброс не подтверждён. Подключение остаётся заблокированным.': 'Reset unconfirmed. Connection remains blocked.',
  'Защита при обрыве, DNS и IPv6 ещё не прошла испытания на Windows. Подключение заблокировано до проверки системного модуля. Запуск службы не подтверждает безопасность трафика.': 'Disconnect protection, DNS and IPv6 have not yet passed Windows tests. Connection is blocked until the system module is verified. A running service does not prove traffic safety.',
  'Диагностика службы': 'Service diagnostics',
  'Локальная проверка не отправляет запросы в интернет и не меняет соединение. Рукопожатие и счётчики — не тест отсутствия утечек.': 'This local check sends no internet requests and does not change the connection. Handshakes and counters are not a leak test.',
  'Проверить службу': 'Check service',
  'Проверка доступна при незавершённой VPN-операции и доверенном модуле.': 'This check requires a pending VPN operation and a trusted module.',
  'Состояние службы ещё не запрошено.': 'Service state has not been requested yet.',
  'Проверка локальной службы…': 'Checking local service…',
  'Служба отсутствует': 'Service is absent',
  'Служба остановлена': 'Service is stopped',
  'Служба запускается': 'Service is starting',
  'Служба работает': 'Service is running',
  'Служба останавливается': 'Service is stopping',
  'Состояние службы неизвестно': 'Service state is unknown',
  'Недавнее рукопожатие есть': 'Recent handshake observed',
  'Недавнего рукопожатия нет': 'No recent handshake',
  'Получено байт': 'Bytes received',
  'Отправлено байт': 'Bytes sent',
  'Статистика туннеля недоступна': 'Tunnel statistics unavailable',
  'Время проверки': 'Checked at',
  'Защита трафика не подтверждена.': 'Traffic protection is unverified.',
  'Состояние не подтверждено: служба недоступна или её ответ отклонён.': 'State unverified: service unavailable or response rejected.',
  'Состояние службы и защита трафика ещё не подтверждены': 'Service state and traffic protection are not yet verified',
  'Правила приложений загружаются. Повторите через несколько секунд.': 'Application rules are loading. Try again in a few seconds.',
  'По профилю': 'Profile routes',
  'Не проверено': 'Unverified',
  'Ожидает проверки': 'Awaiting verification',
  'Служба запущена, но защита трафика не подтверждена': 'Service started, but traffic protection is unverified',
  'Не удалось прочитать правила приложений. Подключение заблокировано.': 'Could not read application rules. Connection is blocked.',
  'Это редактор правил, а не работающая маршрутизация приложений. Правила сохраняются локально. Если включён режим приложений, подключение заблокировано до реализации и проверки сетевого фильтра.': 'This is a rule editor, not working per-app routing. Rules are stored locally. Selecting an application mode blocks connection until the network filter is implemented and verified.',
  'Режим приложений': 'Application mode',
  'Выключено': 'Off',
  'Только выбранные — через VPN': 'Only selected apps through VPN',
  'Выбранные — в обход VPN': 'Selected apps bypass VPN',
  'Поиск в выбранных приложениях': 'Search selected applications',
  'Добавить .exe': 'Add .exe',
  'Сохранить правила': 'Save rules',
  'Удалить приложение из списка': 'Remove application from list',
  'Приложения не выбраны или не найдены': 'No applications selected or found',
  'Сначала отключите туннель': 'Disconnect the tunnel first',
  'Выбор файлов доступен в приложении Windows.': 'File selection is available in the Windows app.',
  'Выбирается только файл: приложение не запускается. Изменения применяются к списку после сохранения.': 'Only the file is selected; the application is not launched. Changes update the list after saving.',
  'Не удалось добавить приложение. Выберите локальный исполняемый файл .exe.': 'Could not add the application. Choose a local executable .exe file.',
  'Правила сохранены локально. Маршрутизация приложений не включена.': 'Rules saved locally. Per-app routing is not enabled.',
  'Не удалось сохранить правила приложений. Проверьте файлы и отключите туннель.': 'Could not save application rules. Check the files and disconnect the tunnel.',
  'Правила приложений сохранены · подключение заблокировано': 'Application rules saved · connection blocked',
  'Ошибка чтения правил · подключение заблокировано': 'Could not read rules · connection blocked',
  'Правила приложений не подтверждены. Подключение заблокировано.': 'Application rules are unverified. Connection is blocked.',
  'Локальное хранилище': 'Local storage',
  'Меню — в разработке': 'Menu — coming later',
  'Меню появится в следующей версии': 'The menu is not available yet',
  'ВАШ КАНАЛ · ВАШИ ПРАВИЛА': 'YOUR CONNECTION · YOUR RULES',
  'Приватность': 'Privacy',
  'без лишнего шума.': 'without the noise.',
  'В клиенте нет аналитики: VPN-соединение идёт к endpoint и DNS, заданным выбранным профилем.': 'No built-in analytics. The VPN uses the endpoint and DNS specified by your selected profile.',
  'Управление туннелем': 'Tunnel controls',
  'Подключить VPN': 'Connect VPN',
  'Отключить VPN': 'Disconnect VPN',
  'Подключить': 'Connect',
  'Отключить': 'Disconnect',
  'Профиль не выбран': 'No profile selected',
  'Маршруты профиля через Velum': 'Profile routes through Velum',
  'По AllowedIPs выбранной конфигурации': 'Using the selected profile’s AllowedIPs',
  'По AllowedIPs конфигурации': 'Using the profile’s AllowedIPs',
  'Профиль и маршруты': 'Profile and routes',
  'ТОЧКА ПОДКЛЮЧЕНИЯ': 'CONNECTION',
  'Выбрать профиль': 'Choose a profile',
  'Импортируйте конфигурацию': 'Import a configuration',
  'Отключено': 'Disconnected',
  'Velum отключён · маршрут системы не проверялся': 'Velum is disconnected · system routing has not been checked',
  'Проверка модуля…': 'Checking the module…',
  'Раздельное туннелирование': 'Split tunneling',
  'Выберите, какой трафик направлять в туннель': 'Choose which traffic uses the tunnel',
  'Политика маршрутизации': 'Routing policy',
  'Всё': 'All',
  'Только сети': 'Only networks',
  'Исключения': 'Exceptions',
  'Будет доступно после проверенного firewall enforcement': 'Requires verified firewall support',
  'Сети CIDR через запятую': 'CIDR networks, separated by commas',
  'Используются все маршруты AllowedIPs профиля. IPv6 требует явного маршрута ::/0.': 'Uses every AllowedIPs route in the profile. IPv6 requires an explicit ::/0 route.',
  'Импорт': 'Import',
  'Маршруты': 'Routes',
  'Протоколы': 'Protocols',
  'Свой сервер': 'Your server',
  'Основная навигация': 'Main navigation',
  'Главная': 'Home',
  'Поделиться': 'Share',
  'Доступ': 'Access',
  'Настройки': 'Settings',
  'Добавить профиль': 'Add a profile',
  'Добавить': 'Add',
  'Назад': 'Back',
  'Раздел': 'Section',
  'Endpoint не указан': 'No endpoint specified',
  'Запускаю…': 'Starting…',
  'Туннель запущен': 'Tunnel started',
  'Отключаю…': 'Disconnecting…',
  'Повторить': 'Retry',
  'Запуск туннеля': 'Starting the tunnel',
  'Служба запущена': 'Service started',
  'Остановка туннеля': 'Stopping the tunnel',
  'Ошибка VPN-службы': 'VPN service error',
  'Передаём конфигурацию локальной службе': 'Sending the configuration to the local service',
  'Handshake и DNS ещё требуют проверки': 'Handshake and DNS still need to be verified',
  'Ожидаем подтверждение локальной службы': 'Waiting for the local service to confirm',
  'Состояние системного туннеля не подтверждено': 'System tunnel status is unverified',
  'Предпросмотр: подключение доступно только в приложении Velum': 'Preview: connect using the Velum app',
  'Подключение недоступно: нужен доверенный модуль Velum': 'Connection unavailable: a trusted Velum module is required',
  'Предпросмотр': 'Preview',
  'Нужен модуль': 'Module required',
  'Демонстрация интерфейса · системный VPN-модуль недоступен в браузере': 'Interface preview · the VPN module is unavailable in a browser',
  'Модуль закреплён · {platform}': 'Pinned module · {platform}',
  'Доверенный модуль не установлен · {platform}': 'Trusted module not installed · {platform}',
  'Локальная служба Velum не ответила': 'The local Velum service did not respond',
  'Не удалось получить состояние локальной службы Velum.': 'Could not read the local Velum service status.',
  'Не удалось открыть защищённое хранилище профилей.': 'Could not open protected profile storage.',
  'Импорт и защищённое хранение готовы': 'Import and protected storage are available',
  'Адаптер в разработке': 'Adapter in development',
  'Только desktop-исследование': 'Desktop research only',
  'Отдельное подключение для пользователя без доступа к управлению сервером.': 'Give a user their own connection without access to server administration.',
  'Сервер': 'Server',
  'Протокол': 'Protocol',
  'Формат подключения': 'Connection format',
  'Velum / совместимый .conf': 'Velum / compatible .conf',
  'Выдача нового доступа ещё не подключена. Импортированный профиль позволяет пользоваться VPN, но не создавать других пользователей.': 'Creating new access is not available yet. An imported profile lets you use the VPN, but does not let you create other users.',
  'Посмотреть протоколы': 'View protocols',
  'Пользователи': 'Users',
  'Список пользователей пока недоступен. Для просмотра, переименования и отзыва доступа требуется подключить управление сервером.': 'The user list is not available yet. Viewing users, renaming them and revoking access require server administration to be connected.',
  'Локальные профили не являются списком пользователей сервера. Существующие подключения здесь не изменяются.': 'Local profiles are not the server’s user list. This screen does not change existing connections.',
  'Не выбран': 'Not selected',
  'Поделиться VPN': 'Share VPN',
  'Раздел доступа': 'Access section',
  'Соединение': 'Connection',
  'Серверы': 'Servers',
  'Протоколы и соединение': 'Protocols and connection',
  'Приложение': 'Application',
  'Безопасность и DNS': 'Security and DNS',
  'Резервная копия': 'Backup',
  'Локальное управление': 'Local management',
  'Настройки и состояние доступных функций — в каждом разделе.': 'Open a section to view its settings and available features.',
  'Ваши профили и настройки подключения в одном приложении.': 'Your profiles and connection settings in one app.',
  'Сборка': 'Build',
  'Предварительная': 'Preview',
  'Оформление': 'Appearance',
  'Тёмное': 'Dark',
  'Хранилище': 'Storage',
  'Сетевой модуль': 'Network module',
  'Ваши данные': 'Your data',
  'В приложении нет встроенной аналитики и автоматической отправки профилей. Импорт в Windows выполняется через системное окно выбора файла.': 'The app has no built-in analytics and does not upload profiles automatically. Windows import uses the system file picker.',
  'Обновить локальное состояние': 'Refresh local status',
  'Это предпросмотр интерфейса в браузере. Локальное хранилище и системный модуль здесь недоступны.': 'This is an interface preview in a browser. Local storage and the system module are unavailable here.',
  'Недоступно в браузере': 'Unavailable in a browser',
  'Доверенный модуль найден': 'Trusted module found',
  'Не установлен': 'Not installed',
  'Защита профилей': 'Profile protection',
  'В Windows импортированные ключи зашифрованы с помощью DPAPI и привязаны к вашей учётной записи. Их содержимое не передаётся в интерфейс приложения.': 'On Windows, imported keys are encrypted with DPAPI and tied to your user account. Their contents are not sent to the app’s interface.',
  'Защита трафика': 'Traffic protection',
  'Kill switch, защита DNS и контроль утечек IPv6 ещё не реализованы. Запуск службы сам по себе не подтверждает защищённое соединение.': 'The kill switch, DNS protection and IPv6 leak controls are not implemented yet. Starting a service alone does not verify a protected connection.',
  'Маршруты и DNS': 'Routes and DNS',
  'Адрес VPN-сервера, DNS и исходные маршруты берутся из выбранного профиля. В настройках маршрутов можно выбрать сети CIDR; фактическая работа требует системного адаптера.': 'The selected profile supplies the VPN server address, DNS and initial routes. You can select CIDR networks in routing settings; applying them requires the system adapter.',
  'Открыть маршруты': 'Open routes',
  'Velum использует один VPN-сервер. Многоузловой маршрутизации Tor и изоляции браузера здесь нет.': 'Velum uses one VPN server. It does not provide Tor’s multi-hop routing or browser isolation.',
  'Сохраните исходный профиль': 'Keep the original profile',
  'Храните полученный .conf или .vpn в защищённом месте. В нём могут находиться приватные ключи — не публикуйте его и не отправляйте посторонним.': 'Keep your .conf or .vpn file in a secure location. It may contain private keys; do not publish it or share it with others.',
  'Перенос на другое устройство': 'Moving to another device',
  'Зашифрованное хранилище DPAPI привязано к пользователю Windows. Простое копирование файлов хранилища не заменяет переносимый архив.': 'Encrypted DPAPI storage is tied to your Windows user account. Copying its files is not a substitute for a portable backup.',
  'Создание и восстановление переносимого архива ещё недоступны. Сейчас можно импортировать исходный файл подключения; существующий профиль не будет перезаписан.': 'Portable backup and restore are not available yet. You can import an original connection file; existing profiles will not be overwritten.',
  'Импортировать профиль': 'Import a profile',
  'Добавьте готовый профиль VPN или узнайте о подключении собственного сервера.': 'Add an existing VPN profile or learn about connecting your own server.',
  'Ключ подключения': 'Connection key',
  'Вставить': 'Paste',
  'Вставка ключа и QR-код пока недоступны. Файл .conf или .vpn можно импортировать ниже.': 'Pasting a key and scanning a QR code are not available yet. Import a .conf or .vpn file below.',
  'ДРУГИЕ ВАРИАНТЫ': 'OTHER OPTIONS',
  'Подключение собственного сервера': 'Connect your own server',
  'Файл подключения': 'Connection file',
  'Импорт .conf или .vpn в Windows': 'Import .conf or .vpn on Windows',
  'Каталог протоколов': 'Protocol catalog',
  'Доступность и поддержка': 'Availability and support',
  'Используйте профиль VPN с собственного сервера.': 'Use a VPN profile from your own server.',
  'Сервер уже настроен': 'Server already configured',
  'Импортируйте совместимый .conf или файл подключения .vpn. Для добавления такого профиля SSH-доступ не нужен.': 'Import a compatible .conf or .vpn connection file. Adding this kind of profile does not require SSH access.',
  'Добавить файл': 'Add a file',
  'Развёртывание в Docker': 'Docker deployment',
  'Серверная часть Velum использует отдельный Docker Compose-проект. Управление развёртыванием через приложение ещё не подключено.': 'The Velum server uses a separate Docker Compose project. Deployment management from the app is not available yet.',
  'SSH-подключение из этого окна пока недоступно. Приложение не запрашивает пароль сервера и не выполняет удалённые команды.': 'SSH connections are not available from this screen yet. The app does not request your server password or run remote commands.',
  'Загрузка локального каталога…': 'Loading the local catalog…',
  'Каталог системных адаптеров доступен в приложении Velum. В браузере показан только интерфейс, подключение VPN здесь недоступно.': 'The system adapter catalog is available in the Velum app. This browser view is only an interface preview and cannot connect to a VPN.',
  'Цель после реализации: GA': 'Target after implementation: GA',
  'Цель после реализации: {track}': 'Target after implementation: {track}',
  'Целевые ОС: {platforms}': 'Target platforms: {platforms}',
  '{implementation} · Целевые ОС: {platforms}': '{implementation} · Target platforms: {platforms}',
  'Не удалось загрузить локальный каталог протоколов. Вернитесь в настройки и повторите попытку.': 'Could not load the local protocol catalog. Return to Settings and try again.',
  'Профиль не открыт: {error}': 'Could not open the profile: {error}',
  'Нативный импорт конфигурации доступен в приложении Velum для Windows.': 'Native configuration import is available in the Velum app for Windows.',
  '{protocol} сохранён локально · {count} AWG-параметров': '{protocol} saved locally · {count} AWG parameters',
  'Профиль отклонён: {error}': 'Profile rejected: {error}',
  'Раздельное туннелирование включено': 'Split tunneling enabled',
  'Только выбранные сети': 'Selected networks only',
  'Через VPN пойдут только указанные сети.': 'Only the specified networks will use the VPN.',
  'Исключения выбраны': 'Exceptions selected',
  'Требуется firewall-модуль': 'Firewall module required',
  'Режим заблокирован до безопасного platform firewall enforcement.': 'This mode is blocked until safe platform firewall support is available.',
  'Туннель отключён': 'Tunnel disconnected',
  'Подключение заблокировано: подписанный и закреплённый модуль Velum ещё не установлен.': 'Connection blocked: the signed, pinned Velum module is not installed yet.',
  'Системная служба приняла конфигурацию. Диагностика доступна в настройках безопасности; защита трафика пока не подтверждена.': 'The system service accepted the configuration. Diagnostics are available in security settings; traffic protection remains unverified.',
  'WireGuard-криптография с DPI-обфускацией AWG 3': 'WireGuard cryptography with AWG 3 DPI obfuscation',
  'Совместимость с существующими профилями AmneziaWG': 'Compatibility with existing AmneziaWG profiles',
  'Быстрый базовый VPN-транспорт': 'Fast, standard VPN transport',
  'Совместимый TLS VPN для ограниченных сетей': 'Compatible TLS VPN for restricted networks',
  'Системный fallback с сертификатной аутентификацией': 'System fallback with certificate authentication',
  'Антиблокировочный прокси через системный TUN': 'Circumvention proxy through the system TUN',
  'SIP022 AEAD proxy через системный TUN': 'SIP022 AEAD proxy through the system TUN',
  'Экспериментальный desktop camouflage transport': 'Experimental desktop camouflage transport',
  'Не удалось безопасно прочитать выбранный файл': 'Could not safely read the selected file',
  'Профиль пуст или превышает 256 KiB': 'The profile is empty or exceeds 256 KiB',
  'Файл изменился во время чтения; повторите импорт': 'The file changed while being read; try importing it again',
  'Не удалось открыть окно выбора файла': 'Could not open the file picker',
  'Нативный импорт и защищённое хранилище пока доступны только в Windows': 'Native import and protected storage are currently available only on Windows',
  'Окно выбора файла вернуло некорректный путь': 'The file picker returned an invalid path',
  'Выберите профиль с расширением .conf или .vpn': 'Choose a profile with the .conf or .vpn extension',
  'Профиль Amnezia отклонён: нужен корректный ключ только для подключения': 'Amnezia profile rejected: a valid connection-only key is required',
  'Профиль содержит некорректный UTF-8': 'The profile contains invalid UTF-8',
  'Профиль WireGuard/AmneziaWG отклонён': 'WireGuard/AmneziaWG profile rejected',
  'Протокол профиля не поддерживается': 'The profile protocol is not supported',
  'Хранилище профилей недоступно': 'Profile storage is unavailable',
  'Не удалось открыть хранилище профилей': 'Could not open profile storage',
  'Не удалось защитить профиль': 'Could not protect the profile',
  'Профиль с этим именем уже существует; перезапись запрещена': 'A profile with this name already exists; overwriting is not allowed',
  'Не удалось создать защищённый профиль': 'Could not create the protected profile',
  'Не удалось сохранить защищённый профиль': 'Could not save the protected profile',
  'Некорректное имя профиля': 'Invalid profile name',
  'Недопустимое имя профиля': 'Invalid profile name',
  'Другой VPN-переход уже выполняется или туннель активен': 'Another VPN operation is in progress or a tunnel is active',
  'VPN-переход уже выполняется': 'A VPN operation is already in progress',
  'Нет активного туннеля': 'No active tunnel',
  'Защищённый профиль пуст или превышает безопасный лимит': 'The protected profile is empty or exceeds the safe size limit',
  'Размер защищённого профиля изменился во время чтения': 'The protected profile changed size while being read',
  'Профиль слишком большой': 'The profile is too large',
  'Защищённое постоянное хранилище пока реализовано только через Windows DPAPI': 'Protected persistent storage is currently implemented only through Windows DPAPI',
  'Подписанный модуль Velum AWG не установлен. Внешние исполняемые файлы Amnezia и пути из окружения намеренно не используются': 'The signed Velum AWG module is not installed. External Amnezia executables and environment-supplied paths are not used',
  'Доверенный root-owned модуль Velum AWG не установлен': 'The trusted, root-owned Velum AWG module is not installed',
  'Системный AWG-драйвер не найден': 'The system AWG driver was not found',
  'Для режима «Только выбранное» укажите хотя бы одну сеть CIDR': 'Specify at least one CIDR network for Selected networks only mode',
  'В этой версии only-selected принимает CIDR; доменные и per-app правила требуют платформенного DNS/firewall адаптера': 'This version supports CIDR networks in selected-only mode; domain and per-app rules require a platform DNS/firewall adapter',
  'В конфигурации не найден Peer.AllowedIPs': 'Peer.AllowedIPs was not found in the configuration',
  'Обнаружен остаточный plaintext-конфиг; подключение заблокировано до безопасного удаления': 'A leftover plaintext configuration was found; connecting is blocked until it is safely removed',
  'Режим исключений требует платформенного firewall enforcement и пока заблокирован во избежание утечки; используйте «Только выбранное»': 'Exceptions require platform firewall enforcement and are blocked to prevent leaks; use Selected networks only',
  'Язык': 'Language',
  'Язык интерфейса': 'Interface language',
  'Русский': 'Russian',
  'Английский': 'English',
  'Закрыть': 'Close',
  'Закрыть панель': 'Close panel',
  'Готово': 'Done',
  'Отмена': 'Cancel',
  'Сохранить': 'Save',
  'Выбрать сервер': 'Choose a server',
  'Выбрать протокол': 'Choose a protocol',
  'Выбрать формат': 'Choose a format',
  'Имя пользователя': 'User name',
  'Новый пользователь': 'New user',
  'Название сервера': 'Server name',
  'Адрес сервера': 'Server address',
  'IP или домен': 'IP address or domain',
  'SSH-порт': 'SSH port',
  'Пользователь SSH': 'SSH user',
  'Пароль SSH': 'SSH password',
  'Добавить сервер': 'Add a server',
  'Создать пользователя': 'Create a user',
  'Создать доступ': 'Create access',
  'Создать подключение': 'Create a connection',
  'Локальный черновик': 'Local draft',
  'Черновик': 'Draft',
  'Недоступно': 'Unavailable',
  'Не настроено': 'Not configured',
  'Нет профилей': 'No profiles',
  'Нет серверов': 'No servers',
  'Подробнее': 'Learn more',
  'Сервер и способы подключения': 'Server and connection methods',
  'Модуль закреплён': 'Pinned module',
  'Доверенный модуль не установлен': 'Trusted module not installed',
  'Раздельное VPN-туннелирование': 'VPN split tunneling',
  'Выберите, какой трафик направлять через VPN, а какой — напрямую.': 'Choose which traffic uses the VPN and which connects directly.',
  'Раздельное туннелирование сайтов': 'Website split tunneling',
  'Сейчас доступны сети CIDR. Правила для доменов ещё не реализованы.': 'CIDR networks are currently supported. Domain rules are not implemented yet.',
  'Раздельное туннелирование приложений': 'App split tunneling',
  'Требуется системный адаптер приложений.': 'A system app-routing adapter is required.',
  'Выбор правил не означает, что VPN подключён. Их применение требует работающего сетевого модуля.': 'Selecting rules does not mean the VPN is connected. Applying them requires a working network module.',
  'Туннелирование приложений': 'App tunneling',
  'Раздельное туннелирование приложений пока недоступно. Нужны правила системного сетевого фильтра и проверка утечек.': 'App split tunneling is not available yet. It requires system network-filter rules and leak testing.',
  'Сайты и сети': 'Websites and networks',
  'Укажите сети CIDR. Доменные имена здесь не принимаются.': 'Enter CIDR networks. Domain names are not accepted here.',
  'Выбраны сети для туннеля': 'Tunnel networks selected',
  'Сервер и подключение': 'Server and connection',
  'Показаны подключения из импортированных файлов, а не полный список протоколов на сервере.': 'These connections come from imported files and are not a complete list of protocols on the server.',
  'Другие варианты подключения': 'Other connection methods',
  'Добавьте файл подключения, чтобы увидеть сервер.': 'Add a connection file to see the server.',
  'Доступны только способы подключения, для которых уже импортирован профиль.': 'Only connection methods with an imported profile are available.',
  'Нельзя выдать пользователю протокол, для которого на выбранном сервере нет подтверждённого подключения.': 'You cannot give a user a protocol without a verified connection on the selected server.',
  'Имя и параметры можно подготовить. Создание пользователя требует доступа к управлению сервером; клиентский конфиг такого доступа не предоставляет.': 'You can prepare the name and settings. Creating a user requires server administration access, which a client configuration does not provide.',
  'Язык приложения': 'App language',
  'Создание пользователя требует доступа к управлению сервером.': 'Creating a user requires server administration access.',
  'Цель после реализации:': 'Target after implementation:',
  'Целевые ОС:': 'Target platforms:',
  'Проверьте имя (до 64 символов без управляющих знаков), сервер и доступный протокол.': 'Check the name (up to 64 characters without control characters), the server and an available protocol.',
  'Профиль сохранён локально': 'Profile saved locally',
  'Профиль отклонён. Проверьте формат файла и отсутствие профиля с таким именем.': 'Profile rejected. Check the file format and make sure a profile with this name does not already exist.',
  'Не удалось отключить туннель. Состояние соединения не подтверждено.': 'Could not disconnect the tunnel. Connection status is unverified.',
  'Не удалось запустить туннель. Проверьте профиль и системный модуль.': 'Could not start the tunnel. Check the profile and system module.',
} satisfies Record<string, string>);

export const ru = Object.freeze(Object.fromEntries(Object.keys(en).map((source) => [source, source])) as Record<string, string>);
export const dictionaries = Object.freeze({ ru, en });

type LanguageStorage = Pick<Storage, 'getItem' | 'setItem'>;
type LanguageDocument = { documentElement: { lang: string } };
let language: Language = DEFAULT_LANGUAGE;
let languageStorage: LanguageStorage | null = null;
let languageDocument: LanguageDocument | null = null;

function browserStorage(): LanguageStorage | null {
  try { return typeof window === 'undefined' ? null : window.localStorage; }
  catch { return null; }
}

function browserDocument(): LanguageDocument | null {
  return typeof document === 'undefined' ? null : document;
}

export function isSupportedLanguage(value: unknown): value is Language {
  return value === 'ru' || value === 'en';
}

export function initLanguage(
  storage: LanguageStorage | null = browserStorage(),
  target: LanguageDocument | null = browserDocument(),
): Language {
  languageStorage = storage;
  languageDocument = target;
  let stored: unknown;
  try { stored = storage?.getItem(LANGUAGE_STORAGE_KEY); }
  catch { stored = null; }
  language = isSupportedLanguage(stored) ? stored : DEFAULT_LANGUAGE;
  if (languageDocument) languageDocument.documentElement.lang = language;
  return language;
}

export function getLanguage(): Language { return language; }

export function setLanguage(choice: unknown): Language {
  language = isSupportedLanguage(choice) ? choice : DEFAULT_LANGUAGE;
  if (languageDocument) languageDocument.documentElement.lang = language;
  try { languageStorage?.setItem(LANGUAGE_STORAGE_KEY, language); }
  catch { /* The selection still works when local storage is blocked. */ }
  return language;
}

export function hasTranslation(source: string): boolean {
  return Object.hasOwn(en, source);
}

/** Returns plain text. Insert dynamic parameter values with textContent, never innerHTML. */
export function t(source: string, params: TranslationParams = {}): string {
  const translated = language === 'en' && hasTranslation(source) ? en[source as keyof typeof en] : source;
  return translated.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (placeholder, name: string) => (
    Object.hasOwn(params, name) ? String(params[name]) : placeholder
  ));
}

const translatedAttributes = ['title', 'aria-label', 'placeholder'] as const;
const translationSelector = ['[data-i18n]', ...translatedAttributes.map((attribute) => `[data-i18n-${attribute}]`)].join(',');
const dynamicIds = [
  'orb-label', 'orb-detail', 'state-label', 'security-detail', 'driver-state',
  'endpoint', 'protocol-chip', 'profile-name', 'screen-title',
  'policy-hint', 'split-label', 'split-detail',
];
const excludedSelector = ['[data-dynamic]', 'script', 'style', 'textarea', 'code', 'pre', 'noscript', ...dynamicIds.map((id) => `#${id}`)].join(',');

function isExcluded(node: Element): boolean { return node.closest(excludedSelector) !== null; }

/**
 * Use ONLY for application-owned static markup, before inserting any profile or
 * server data. Runtime data must be inserted separately with textContent and
 * marked data-dynamic. Unknown copy is neither translated nor annotated.
 */
export function localizeStaticMarkup(markup: string): string {
  if (typeof document === 'undefined') return markup;
  const template = document.createElement('template');
  template.innerHTML = markup;
  for (const node of template.content.querySelectorAll<HTMLElement>('*')) {
    if (isExcluded(node)) continue;
    for (const attribute of translatedAttributes) {
      const source = node.getAttribute(attribute);
      if (source !== null && hasTranslation(source.trim())) {
        node.setAttribute(`data-i18n-${attribute}`, source.trim());
        node.setAttribute(attribute, t(source.trim()));
      }
    }
  }
  const walker = document.createTreeWalker(template.content, 4 /* NodeFilter.SHOW_TEXT */);
  const textNodes: Text[] = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode as Text);
  for (const node of textNodes) {
    const parent = node.parentElement;
    if (parent && isExcluded(parent)) continue;
    const source = node.data.trim();
    if (!hasTranslation(source)) continue;
    const prefix = node.data.slice(0, node.data.indexOf(source));
    const suffix = node.data.slice(prefix.length + source.length);
    if (parent && parent.childNodes.length === 1) {
      parent.setAttribute('data-i18n', source);
      node.data = `${prefix}${t(source)}${suffix}`;
    } else {
      const label = document.createElement('span');
      label.setAttribute('data-i18n', source);
      label.textContent = t(source);
      node.replaceWith(document.createTextNode(prefix), label, document.createTextNode(suffix));
    }
  }
  return template.innerHTML;
}

/** Opt-in only: user-provided names, addresses and unmarked DOM are never inspected. */
export function applyTranslations(root: ParentNode = document): void {
  const nodes = Array.from(root.querySelectorAll<HTMLElement>(translationSelector));
  if ('matches' in root && typeof root.matches === 'function' && root.matches(translationSelector)) {
    nodes.unshift(root as HTMLElement);
  }
  for (const node of nodes) {
    if (isExcluded(node)) continue;
    const source = node.getAttribute('data-i18n');
    // Explicit leaf labels only: do not destroy nested controls or profile data.
    if (source !== null && node.childElementCount === 0) node.textContent = t(source);
    for (const attribute of translatedAttributes) {
      const attributeSource = node.getAttribute(`data-i18n-${attribute}`);
      if (attributeSource !== null) node.setAttribute(attribute, t(attributeSource));
    }
  }
}

initLanguage();
