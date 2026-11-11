import './style.css';
import { invoke } from '@tauri-apps/api/core';
import { installScrollActivity } from './scroll-activity';
import { createBottomSheet } from './bottom-sheet';
import { initLanguage, getLanguage, setLanguage, t, applyTranslations, localizeStaticMarkup } from './i18n';
import { deriveServers, validatePeerDraft, validatePeerProvisioning, type ServerTarget } from './server-capabilities';
import {
  ChevronDown,
  ChevronRight,
  Download,
  Gauge,
  Home,
  Import,
  Layers3,
  LockKeyhole,
  Menu,
  Plus,
  Route,
  Server,
  Settings2,
  Share2,
  ShieldCheck,
  SlidersHorizontal,
  Wifi,
  createElement,
} from 'lucide';

type ConnectionState = 'disconnected' | 'connecting' | 'awaiting_verification' | 'connected' | 'disconnecting' | 'error';
type Status = {
  state: ConnectionState;
  profile?: string;
  message?: string;
  platform: string;
  backend_trusted: boolean;
};
type BackendObservation = {
  service_state: 'absent' | 'stopped' | 'start_pending' | 'running' | 'stop_pending' | 'unknown';
  uapi_state: 'not_running' | 'unavailable' | 'available';
  config_accepted: boolean;
  handshake_fresh: boolean;
  peer_count: string;
  rx_bytes: string;
  tx_bytes: string;
  observed_at_unix_seconds: number;
  traffic_verified: false;
};
type Summary = {
  fingerprint: string;
  addresses: string[];
  endpoints: string[];
  awg_parameters: string[];
};
type StoredProfile = { name: string; protocol: string; summary: Summary };
type SelectedApplication = { id: string; name: string; path: string };
type ApplicationRules = { schema_version: 1; mode: 'off' | 'include' | 'exclude'; applications: SelectedApplication[] };
type ProtocolDescriptor = {
  id: string;
  name: string;
  summary: string;
  target_release_track: 'general_availability' | 'preview' | 'beta' | 'experimental';
  implementation: 'import_and_storage' | 'catalogued' | 'desktop_research';
  target_platforms: string[];
  config_formats: string[];
  docker_server: boolean;
};

const icons = {
  ChevronDown,
  ChevronRight,
  Download,
  Gauge,
  Home,
  Import,
  Layers3,
  LockKeyhole,
  Menu,
  Plus,
  Route,
  Server,
  Settings2,
  Share2,
  ShieldCheck,
  SlidersHorizontal,
  Wifi,
};

const icon = (name: keyof typeof icons, size = 18) => {
  const node = createElement(icons[name]);
  node.setAttribute('width', String(size));
  node.setAttribute('height', String(size));
  node.setAttribute('stroke-width', '1.8');
  node.setAttribute('aria-hidden', 'true');
  return node.outerHTML;
};

const app = document.querySelector<HTMLDivElement>('#app')!;
initLanguage();
app.innerHTML = localizeStaticMarkup(`
  <main class="velum-shell">
    <header class="topbar">
      <div class="brand" aria-label="Velum VPN">
        <span class="brand-mark"><i></i><b>V</b></span>
        <span><strong>VELUM</strong><small>PRIVATE NETWORK</small></span>
      </div>
      <div class="top-actions">
        <span class="local-only">${icon('LockKeyhole', 14)} Локальное хранилище</span>
        <button class="icon-button" type="button" aria-label="Меню — в разработке" title="Меню появится в следующей версии" disabled>${icon('Menu', 20)}</button>
      </div>
    </header>

    <section class="home-view">
      <div class="hero-copy">
        <p>ВАШ КАНАЛ · ВАШИ ПРАВИЛА</p>
        <h1>Приватность<br><em>без лишнего шума.</em></h1>
        <span>В клиенте нет аналитики: VPN-соединение идёт к endpoint и DNS, заданным выбранным профилем.</span>
      </div>

      <section class="connection-zone" aria-label="Управление туннелем">
        <div class="orb-wrap">
          <span class="orbit orbit-a"></span>
          <span class="orbit orbit-b"></span>
          <button id="power" class="power-orb" type="button" aria-label="Подключить VPN" aria-describedby="security-detail driver-state" aria-pressed="false" aria-busy="false">
            <span class="orb-kicker">VELUM</span>
            <strong id="orb-label" data-dynamic>Подключить</strong>
            <small id="orb-detail" data-dynamic>Профиль не выбран</small>
          </button>
        </div>

        <button id="split-shortcut" class="split-shortcut" type="button" aria-expanded="false" aria-controls="bottom-sheet" aria-haspopup="dialog">
          <span class="split-icon">${icon('SlidersHorizontal', 17)}</span>
          <span><strong id="split-label" data-dynamic>Маршруты профиля через Velum</strong><small id="split-detail" data-dynamic>По AllowedIPs выбранной конфигурации</small></span>
          ${icon('ChevronDown', 17)}
        </button>
      </section>

      <aside class="server-sheet" aria-label="Профиль и маршруты">
        <div class="sheet-handle" aria-hidden="true"></div>

        <div class="profile-row">
          <span class="server-icon">${icon('Server', 22)}</span>
          <button id="profile-select" class="profile-select-wrap profile-trigger" type="button" aria-haspopup="dialog" aria-controls="bottom-sheet" aria-label="Сервер и способы подключения">
            <span>ТОЧКА ПОДКЛЮЧЕНИЯ</span>
            <strong id="profile-name" data-dynamic>Профиль не выбран</strong>
          </button>
          <span class="select-chevron">${icon('ChevronDown', 19)}</span>
        </div>

        <div class="server-meta">
          <span class="protocol-chip" id="protocol-chip" data-dynamic>Профиль не выбран</span>
          <span class="meta-dot"></span>
          <span id="endpoint" data-dynamic>Импортируйте конфигурацию</span>
        </div>

        <div class="security-line">
          <span class="status-led"></span>
          <span><strong id="state-label" data-dynamic>Отключено</strong><small id="security-detail" data-dynamic aria-live="polite">Velum отключён · маршрут системы не проверялся</small></span>
          <span class="driver-state" id="driver-state" data-dynamic>Проверка модуля…</span>
        </div>

        <section class="route-panel" id="route-panel" hidden>
          <div class="panel-heading">
            <span>${icon('Route', 18)}</span>
            <div><strong>Раздельное туннелирование</strong><small>Выберите, какой трафик направлять в туннель</small></div>
          </div>
          <div class="segments" role="group" aria-label="Политика маршрутизации">
            <button class="selected" data-policy="profile_routes" type="button" aria-pressed="true">По профилю</button>
            <button data-policy="only_selected" type="button" aria-pressed="false">Только сети</button>
            <button data-policy="bypass_selected" type="button" aria-pressed="false" disabled title="Будет доступно после проверенного firewall enforcement">Исключения</button>
          </div>
          <label class="network-field">
            <span>Сети CIDR через запятую</span>
            <input id="networks" placeholder="10.0.0.0/8, 192.168.1.0/24" disabled>
          </label>
        <p class="policy-hint" id="policy-hint" data-dynamic>Используются все маршруты AllowedIPs профиля. IPv6 требует явного маршрута ::/0.</p>
        </section>

        <div class="quick-actions">
          <button data-action="import" type="button"><span>${icon('Download', 18)}</span><small>Импорт</small></button>
          <button data-action="routes" type="button"><span>${icon('Route', 18)}</span><small>Маршруты</small></button>
          <button data-action="protocols" type="button"><span>${icon('Layers3', 18)}</span><small>Протоколы</small></button>
          <button data-action="server" type="button"><span>${icon('Server', 18)}</span><small>Свой сервер</small></button>
        </div>

        <nav class="bottom-nav" aria-label="Основная навигация">
          <button class="active" data-action="home" type="button" aria-label="Главная" aria-current="page">${icon('Home', 22)}<small>Главная</small></button>
          <button data-action="share" type="button" aria-label="Поделиться">${icon('Share2', 22)}<small>Доступ</small></button>
          <button data-action="settings" type="button" aria-label="Настройки">${icon('Settings2', 22)}<small>Настройки</small></button>
          <button data-action="add" type="button" aria-label="Добавить профиль">${icon('Plus', 24)}<small>Добавить</small></button>
        </nav>
      </aside>
    </section>

    <section class="secondary-screen" id="secondary-screen" hidden>
      <header class="screen-header">
        <button id="screen-back" class="icon-button" type="button" aria-label="Назад">${icon('ChevronRight', 20)}</button>
        <h2 id="screen-title" data-dynamic tabindex="-1">Раздел</h2>
      </header>
      <div class="screen-content" id="screen-content"></div>
      <nav class="screen-bottom-nav bottom-nav" aria-label="Основная навигация">
        <button data-screen="home" type="button">${icon('Home', 22)}<small>Главная</small></button>
        <button data-screen="share" type="button">${icon('Share2', 22)}<small>Доступ</small></button>
        <button data-screen="settings" type="button">${icon('Settings2', 22)}<small>Настройки</small></button>
        <button data-screen="add" type="button">${icon('Plus', 24)}<small>Добавить</small></button>
      </nav>
    </section>

    <dialog id="bottom-sheet" class="bottom-sheet" aria-labelledby="sheet-title">
      <div class="sheet-drag-handle" aria-hidden="true"></div>
      <header class="sheet-header">
        <button class="sheet-back icon-button" type="button" aria-label="Назад" hidden>${icon('ChevronRight', 20)}</button>
        <h2 id="sheet-title" data-dynamic tabindex="-1"></h2>
        <button class="sheet-close icon-button" type="button" aria-label="Закрыть">×</button>
      </header>
      <div id="sheet-content" class="sheet-content"></div>
    </dialog>

    <div class="toast" id="toast" role="status" aria-live="polite"></div>
  </main>`);

installScrollActivity(document);

let profileName = '';
let storedProfiles: StoredProfile[] = [];
const tauriRuntimeAvailable = '__TAURI_INTERNALS__' in window;
let status: Status = {
  state: 'disconnected',
  platform: tauriRuntimeAvailable ? 'unknown' : 'browser preview',
  backend_trusted: false,
};
let policy = 'profile_routes';
let applicationRules: ApplicationRules = { schema_version: 1, mode: 'off', applications: [] };
let applicationRulesLoaded = !tauriRuntimeAvailable;
let applicationRulesFailed = false;
let applicationRulesBusy = false;
const appRulesBlockConnect = () => !applicationRulesLoaded || applicationRulesFailed || applicationRules.mode !== 'off';

const query = <T extends Element>(selector: string) => document.querySelector<T>(selector)!;
const sheet = createBottomSheet(query<HTMLDialogElement>('#bottom-sheet'));
const routePanel = query<HTMLElement>('#route-panel');
const routeStorage = document.createElement('div');
routeStorage.hidden = true;
app.append(routeStorage);
routeStorage.append(routePanel);

const toast = (message: string, error = false) => {
  const element = query<HTMLDivElement>('#toast');
  element.textContent = t(message);
  element.setAttribute('role', error ? 'alert' : 'status');
  element.setAttribute('aria-live', error ? 'assertive' : 'polite');
  element.className = `toast show ${error ? 'error' : ''}`;
  window.setTimeout(() => {
    element.className = 'toast';
    element.setAttribute('role', 'status');
    element.setAttribute('aria-live', 'polite');
  }, 4200);
};

const endpointFor = (profile?: StoredProfile) => profile?.summary.endpoints[0] ?? t('Endpoint не указан');
const protocolLabel = (protocol?: string) => t(({
  amnezia_wg3: 'AmneziaWG 3.0',
  amnezia_wg_legacy: 'AmneziaWG 1/2',
  wire_guard: 'WireGuard',
}[protocol ?? ''] ?? 'VPN profile'));

const render = () => {
  const labels: Record<ConnectionState, string> = {
    disconnected: 'Подключить',
    connecting: 'Запускаю…',
    awaiting_verification: 'Не проверено',
    connected: 'Туннель запущен',
    disconnecting: 'Отключаю…',
    error: 'Повторить',
  };
  const stateLabels: Record<ConnectionState, string> = {
    disconnected: 'Отключено',
    connecting: 'Запуск туннеля',
    awaiting_verification: 'Ожидает проверки',
    connected: 'Служба запущена',
    disconnecting: 'Остановка туннеля',
    error: 'Ошибка VPN-службы',
  };
  const securityLabels: Record<ConnectionState, string> = {
    disconnected: 'Velum отключён · маршрут системы не проверялся',
    connecting: 'Передаём конфигурацию локальной службе',
    awaiting_verification: 'Состояние службы и защита трафика ещё не подтверждены',
    connected: 'Handshake и DNS ещё требуют проверки',
    disconnecting: 'Ожидаем подтверждение локальной службы',
    error: status.message ?? 'Состояние системного туннеля не подтверждено',
  };

  const root = query<HTMLElement>('.velum-shell');
  root.dataset.state = status.state;
  query('#orb-label').textContent = t(labels[status.state]);
  query('#orb-detail').textContent = profileName || t('Профиль не выбран');
  query('#profile-name').textContent = profileName || t('Профиль не выбран');
  query('#state-label').textContent = t(stateLabels[status.state]);
  query('#security-detail').textContent = t(securityLabels[status.state]);
  const power = query<HTMLButtonElement>('#power');
  const hasActiveTunnel = Boolean(status.profile);
  const transitionActive = status.state === 'connecting' || status.state === 'disconnecting';
  const runtimeBlocked = !tauriRuntimeAvailable;
  const backendBlocked = runtimeBlocked || (Boolean(profileName) && !status.backend_trusted && !hasActiveTunnel);
  power.disabled = backendBlocked || transitionActive || (!hasActiveTunnel && appRulesBlockConnect());
  power.setAttribute(
    'aria-label',
    t(runtimeBlocked
      ? 'Предпросмотр: подключение доступно только в приложении Velum'
      : backendBlocked
        ? 'Подключение недоступно: нужен доверенный модуль Velum'
        : hasActiveTunnel
          ? 'Отключить VPN'
          : 'Подключить VPN'),
  );
  power.setAttribute('aria-pressed', String(hasActiveTunnel));
  power.setAttribute('aria-busy', String(transitionActive));
  if (runtimeBlocked) query('#orb-label').textContent = t('Предпросмотр');
  else if (backendBlocked) query('#orb-label').textContent = t('Нужен модуль');
  query<HTMLButtonElement>('#profile-select').disabled = hasActiveTunnel || transitionActive;
  document.querySelectorAll<HTMLButtonElement>('[data-policy]').forEach(button => {
    button.disabled = hasActiveTunnel || transitionActive || button.dataset.policy === 'bypass_selected';
  });
  query<HTMLInputElement>('#networks').disabled = hasActiveTunnel || transitionActive || policy === 'profile_routes';
  query('#driver-state').textContent = runtimeBlocked
    ? t('Демонстрация интерфейса · системный VPN-модуль недоступен в браузере')
    : status.backend_trusted
      ? `${t('Модуль закреплён')} · ${status.platform}`
      : `${t('Доверенный модуль не установлен')} · ${status.platform}`;
  const selected = storedProfiles.find(profile => profile.name === profileName);
  query('#endpoint').textContent = selected ? endpointFor(selected) : t('Импортируйте конфигурацию');
  query('#protocol-chip').textContent = selected ? protocolLabel(selected.protocol) : t('Профиль не выбран');
  renderPolicy();
};

async function refresh() {
  if (!tauriRuntimeAvailable) {
    render();
    return;
  }
  try {
    status = await invoke<Status>('tunnel_status');
    if (status.profile) profileName = status.profile;
    render();
  } catch {
    status.state = 'error';
    status.message = 'Локальная служба Velum не ответила';
    render();
    toast('Не удалось получить состояние локальной службы Velum.', true);
  }
}

async function openStoredProfile(name: string) {
  const profile = storedProfiles.find((candidate) => candidate.name === name);
  if (!profile) {
    profileName = '';
    render();
    return;
  }
  profileName = profile.name;
  query('#endpoint').textContent = endpointFor(profile);
  query('#protocol-chip').textContent = protocolLabel(profile.protocol);
  render();
}

async function loadStoredProfiles(preferredName?: string) {
  if (!tauriRuntimeAvailable) {
    storedProfiles = [];
    render();
    return;
  }
  try {
    storedProfiles = await invoke<StoredProfile[]>('list_profiles');
    const nextName = preferredName || profileName || storedProfiles[0]?.name;
    if (nextName) await openStoredProfile(nextName);
  } catch {
    toast('Не удалось открыть защищённое хранилище профилей.', true);
  }
}

function toggleRoutes(force?: boolean) {
  if (force === false) sheet.close();
  else openSplitSheet();
}

function setSheetContent(container: HTMLElement, markup: string) {
  container.innerHTML = localizeStaticMarkup(markup);
}

function openSheet(title: string, renderContent: (container: HTMLElement) => void, back?: () => void, cleanup?: () => void) {
  sheet.open({
    title: t(title),
    render: renderContent,
    onClose: () => {
      cleanup?.();
      query('#split-shortcut').setAttribute('aria-expanded', 'false');
    },
  });
  const backButton = query<HTMLButtonElement>('.sheet-back');
  backButton.hidden = !back;
  backButton.onclick = back ?? null;
}

function addChoice(container: HTMLElement, label: string, detail: string, selected: boolean, choose: () => void, disabled = false) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'sheet-option';
  button.disabled = disabled;
  button.setAttribute('role', 'radio');
  button.setAttribute('aria-checked', String(selected));
  button.innerHTML = '<span class="sheet-option-main"><strong></strong><small></small></span><span class="sheet-check" aria-hidden="true"></span>';
  button.querySelector('strong')!.textContent = label;
  button.querySelector('small')!.textContent = detail;
  button.querySelector('.sheet-check')!.textContent = selected ? '✓' : '';
  button.addEventListener('click', choose);
  container.append(button);
}

function openSplitSheet() {
  openSheet('Раздельное VPN-туннелирование', container => {
    setSheetContent(container, `
      <p class="screen-lead">Выберите, какой трафик направлять через VPN, а какой — напрямую.</p>
      <div class="settings-list">
        <button data-split="sites" type="button"><span><b>Раздельное туннелирование сайтов</b></span>${icon('ChevronRight', 20)}</button>
        <p class="form-note">Сейчас доступны сети CIDR. Правила для доменов ещё не реализованы.</p>
        <button data-split="apps" type="button"><span><b>Раздельное туннелирование приложений</b></span>${icon('ChevronRight', 20)}</button>
        <p class="form-note">Требуется системный адаптер приложений.</p>
      </div>
      <div class="screen-notice">Выбор правил не означает, что VPN подключён. Их применение требует работающего сетевого модуля.</div>`);
    container.querySelector('[data-split="sites"]')!.addEventListener('click', openNetworkSheet);
    container.querySelector('[data-split="apps"]')!.addEventListener('click', openApplicationSheet);
  });
  query('#split-shortcut').setAttribute('aria-expanded', 'true');
}

async function loadApplicationRules() {
  if (!tauriRuntimeAvailable) return;
  try {
    applicationRules = await invoke<ApplicationRules>('load_application_rules');
    applicationRulesFailed = false;
  } catch {
    applicationRulesFailed = true;
    toast('Не удалось прочитать правила приложений. Подключение заблокировано.', true);
  } finally {
    applicationRulesLoaded = true;
    render();
  }
}

function openApplicationSheet() {
  if (!applicationRulesLoaded || applicationRulesBusy) {
    toast('Правила приложений загружаются. Повторите через несколько секунд.');
    return;
  }
  const draft: ApplicationRules = structuredClone(applicationRules);
  let busy = false;
  const locked = () => Boolean(status.profile) || status.state === 'connecting' || status.state === 'disconnecting';
  openSheet('Туннелирование приложений', container => {
    setSheetContent(container, `
      <div class="screen-notice app-rules-warning">Это редактор правил, а не работающая маршрутизация приложений. Правила сохраняются локально. Если включён режим приложений, подключение заблокировано до реализации и проверки сетевого фильтра.</div>
      <fieldset class="app-modes"><legend>Режим приложений</legend>
        <label><input type="radio" name="app-mode" value="off"><span>Выключено</span></label>
        <label><input type="radio" name="app-mode" value="include"><span>Только выбранные — через VPN</span></label>
        <label><input type="radio" name="app-mode" value="exclude"><span>Выбранные — в обход VPN</span></label>
      </fieldset>
      <label class="network-field"><span>Поиск в выбранных приложениях</span><input id="app-search" type="search" autocomplete="off" spellcheck="false"></label>
      <div id="app-rules-list" class="app-rules-list"></div>
      <p id="app-rules-note" class="form-note" role="status"></p>
      <div class="app-rule-actions">
        <button id="add-application" class="inline-action" type="button">Добавить .exe ${icon('Plus', 18)}</button>
        <button id="save-applications" class="inline-action" type="button">Сохранить правила</button>
      </div>
      <div id="app-rules-recovery" hidden>
        <p class="form-note">Если правила не читаются, можно явно сбросить список. VPN-профили и ключи останутся без изменений.</p>
        <button id="reset-applications" class="inline-action" type="button">Сбросить правила приложений</button>
        <div id="confirm-app-reset" hidden>
          <p>Сохранённый список приложений будет заменён пустым списком, режим приложений будет выключен.</p>
          <button id="confirm-reset-applications" class="inline-action" type="button">Подтвердить сброс</button>
          <button id="cancel-reset-applications" class="inline-action" type="button">Отмена</button>
        </div>
      </div>`);
    const list = container.querySelector<HTMLElement>('#app-rules-list')!;
    const note = container.querySelector<HTMLElement>('#app-rules-note')!;
    const search = container.querySelector<HTMLInputElement>('#app-search')!;
    const add = container.querySelector<HTMLButtonElement>('#add-application')!;
    const save = container.querySelector<HTMLButtonElement>('#save-applications')!;
    const redraw = () => {
      // A late picker/save callback must not redraw a newer bottom-sheet view.
      if (container.querySelector('#save-applications') !== save) return;
      const unavailable = !tauriRuntimeAvailable || !applicationRulesLoaded || applicationRulesFailed || locked() || busy;
      container.querySelectorAll<HTMLInputElement>('input[name="app-mode"]').forEach(input => {
        input.checked = input.value === draft.mode;
        input.disabled = unavailable;
      });
      add.disabled = unavailable || draft.applications.length >= 128;
      save.disabled = unavailable || (draft.mode !== 'off' && !draft.applications.length);
      container.querySelector<HTMLElement>('#app-rules-recovery')!.hidden = !applicationRulesFailed;
      container.querySelectorAll<HTMLButtonElement>('#app-rules-recovery button').forEach(button => {
        button.disabled = !tauriRuntimeAvailable || locked() || busy;
      });
      list.replaceChildren();
      const filter = search.value.toLocaleLowerCase();
      const matches = draft.applications.filter(item => `${item.name} ${item.path}`.toLocaleLowerCase().includes(filter));
      for (const item of matches) {
        const row = document.createElement('article');
        row.className = 'application-rule';
        row.innerHTML = '<div data-dynamic><strong></strong><small></small></div><button type="button">×</button>';
        row.querySelector('strong')!.textContent = item.name;
        row.querySelector('small')!.textContent = item.path;
        const remove = row.querySelector('button')!;
        remove.setAttribute('aria-label', t('Удалить приложение из списка'));
        remove.disabled = unavailable;
        remove.addEventListener('click', () => {
          draft.applications = draft.applications.filter(candidate => candidate.id !== item.id);
          redraw();
        });
        list.append(row);
      }
      if (!matches.length) {
        const empty = document.createElement('p');
        empty.className = 'form-note';
        empty.textContent = t('Приложения не выбраны или не найдены');
        list.append(empty);
      }
      note.textContent = t(applicationRulesFailed
        ? 'Не удалось прочитать правила приложений. Подключение заблокировано.'
        : locked() ? 'Сначала отключите туннель'
        : !tauriRuntimeAvailable ? 'Выбор файлов доступен в приложении Windows.'
        : 'Выбирается только файл: приложение не запускается. Изменения применяются к списку после сохранения.');
    };
    search.addEventListener('input', redraw);
    container.querySelectorAll<HTMLInputElement>('input[name="app-mode"]').forEach(input => input.addEventListener('change', () => {
      draft.mode = input.value as ApplicationRules['mode'];
      redraw();
    }));
    add.addEventListener('click', async () => {
      busy = true;
      applicationRulesBusy = true;
      redraw();
      try {
        const selected = await invoke<SelectedApplication | null>('select_application');
        if (selected && !draft.applications.some(item => item.id === selected.id)) draft.applications.push(selected);
      } catch {
        toast('Не удалось добавить приложение. Выберите локальный исполняемый файл .exe.', true);
      } finally {
        busy = false;
        applicationRulesBusy = false;
        redraw();
      }
    });
    save.addEventListener('click', async () => {
      busy = true;
      applicationRulesBusy = true;
      redraw();
      try {
        applicationRules = await invoke<ApplicationRules>('save_application_rules', { rules: draft });
        render();
        toast('Правила сохранены локально. Маршрутизация приложений не включена.');
      } catch {
        toast('Не удалось сохранить правила приложений. Проверьте файлы и отключите туннель.', true);
      } finally {
        busy = false;
        applicationRulesBusy = false;
        redraw();
      }
    });
    const confirmation = container.querySelector<HTMLElement>('#confirm-app-reset')!;
    container.querySelector('#reset-applications')!.addEventListener('click', () => {
      confirmation.hidden = false;
      container.querySelector<HTMLButtonElement>('#confirm-reset-applications')!.focus();
    });
    container.querySelector('#cancel-reset-applications')!.addEventListener('click', () => { confirmation.hidden = true; });
    container.querySelector('#confirm-reset-applications')!.addEventListener('click', async () => {
      if (!applicationRulesFailed || locked() || busy) return;
      busy = true;
      applicationRulesBusy = true;
      redraw();
      try {
        await invoke<ApplicationRules>('save_application_rules', { rules: { schema_version: 1, mode: 'off', applications: [] } });
        // Recovery is not successful until the native encrypted store can be
        // read again. No transition to Off on a failed/ambiguous IPC response.
        applicationRules = await invoke<ApplicationRules>('load_application_rules');
        applicationRulesFailed = false;
        draft.mode = applicationRules.mode;
        draft.applications = structuredClone(applicationRules.applications);
        confirmation.hidden = true;
        toast('Правила приложений сброшены. VPN-профили не изменены.');
      } catch {
        applicationRulesFailed = true;
        toast('Сброс не подтверждён. Подключение остаётся заблокированным.', true);
      } finally {
        busy = false;
        applicationRulesBusy = false;
        render();
        redraw();
      }
    });
    redraw();
  }, openSplitSheet);
}

function openNetworkSheet() {
  openSheet('Сайты и сети', container => {
    setSheetContent(container, '<p class="screen-lead">Укажите сети CIDR. Доменные имена здесь не принимаются.</p>');
    routePanel.hidden = false;
    container.append(routePanel);
    applyTranslations(routePanel);
    renderPolicy();
  }, openSplitSheet, () => {
    routePanel.hidden = true;
    routeStorage.append(routePanel);
  });
}

function renderPolicy() {
  const copy = policy === 'only_selected'
    ? ['Выбраны сети для туннеля', 'Только выбранные сети', 'Через VPN пойдут только указанные сети.']
    : ['Раздельное туннелирование', 'По AllowedIPs конфигурации', 'Используются все маршруты AllowedIPs профиля. IPv6 требует явного маршрута ::/0.'];
  query('#split-label').textContent = t(copy[0]);
  query('#split-detail').textContent = t(copy[1]);
  if (applicationRules.mode !== 'off') query('#split-detail').textContent = t('Правила приложений сохранены · подключение заблокировано');
  if (applicationRulesFailed) query('#split-detail').textContent = t('Ошибка чтения правил · подключение заблокировано');
  query('#policy-hint').textContent = t(copy[2]);
}

const serverTargets = () => deriveServers(storedProfiles);
const currentTarget = () => serverTargets().find(server => server.profiles.some(profile => profile.name === profileName));

function openServerSheet() {
  openSheet('Сервер и подключение', container => {
    const servers = serverTargets();
    const selected = currentTarget();
    setSheetContent(container, `
      <div class="server-summary"><h3 data-selected-server></h3><p data-selected-endpoint></p>
        <button class="inline-action" id="server-protocol-picker" type="button"><span data-selected-protocol></span>${icon('ChevronDown', 18)}</button>
      </div>
      <h3>Серверы</h3><div class="sheet-list" id="available-servers" role="radiogroup" aria-label="Серверы"></div>
      <div class="screen-notice">Показаны подключения из импортированных файлов, а не полный список протоколов на сервере.</div>
      <button class="inline-action" id="sheet-add-connection" type="button">Другие варианты подключения ${icon('Plus', 18)}</button>`);
    container.querySelector('[data-selected-server]')!.textContent = selected?.label ?? t('Профиль не выбран');
    container.querySelector('[data-selected-endpoint]')!.textContent = selected?.endpoint ?? t('Endpoint не указан');
    container.querySelector('[data-selected-protocol]')!.textContent = protocolLabel(storedProfiles.find(p => p.name === profileName)?.protocol);
    const protocolButton = container.querySelector<HTMLButtonElement>('#server-protocol-picker')!;
    protocolButton.disabled = !selected;
    protocolButton.addEventListener('click', () => { if (selected) openConnectionProtocols(selected); });
    const list = container.querySelector<HTMLElement>('#available-servers')!;
    if (!servers.length) list.textContent = t('Добавьте файл подключения, чтобы увидеть сервер.');
    for (const server of servers) {
      addChoice(list, server.label, server.endpoint ?? t('Endpoint не указан'), server.id === selected?.id, async () => {
        await openStoredProfile(server.profiles[0].name);
        openServerSheet();
      });
    }
    container.querySelector('#sheet-add-connection')!.addEventListener('click', () => showScreen('add'));
  });
}

function openConnectionProtocols(server: ServerTarget) {
  openSheet('Протокол', container => {
    setSheetContent(container, '<p class="screen-lead">Доступны только способы подключения, для которых уже импортирован профиль.</p><div class="sheet-list" role="radiogroup"></div>');
    const list = container.querySelector<HTMLElement>('.sheet-list')!;
    for (const profile of server.profiles) {
      addChoice(list, protocolLabel(profile.protocol), profile.name, profile.name === profileName, async () => {
        await openStoredProfile(profile.name);
        sheet.close();
      });
    }
  }, openServerSheet);
}

let peerDraft = { name: '', serverId: '', protocol: '' };
function syncPeerDraft() {
  const servers = serverTargets();
  const server = servers.find(item => item.id === peerDraft.serverId) ?? currentTarget() ?? servers[0];
  peerDraft.serverId = server?.id ?? '';
  if (!server?.protocols.some(protocol => protocol.id === peerDraft.protocol)) peerDraft.protocol = server?.protocols[0]?.id ?? '';
  return { servers, server };
}

function openPeerServers() {
  const { servers } = syncPeerDraft();
  openSheet('Сервер', container => {
    setSheetContent(container, '<div class="sheet-list" role="radiogroup"></div>');
    const list = container.querySelector<HTMLElement>('.sheet-list')!;
    for (const server of servers) addChoice(list, server.label, server.endpoint ?? '', server.id === peerDraft.serverId, () => {
      peerDraft.serverId = server.id;
      peerDraft.protocol = server.protocols[0]?.id ?? '';
      renderSharePanel();
      sheet.close();
    });
  });
}

function openPeerProtocols() {
  const { server } = syncPeerDraft();
  openSheet('Протокол', container => {
    setSheetContent(container, '<div class="sheet-list" role="radiogroup"></div><p class="form-note">Нельзя выдать пользователю протокол, для которого на выбранном сервере нет подтверждённого подключения.</p>');
    const list = container.querySelector<HTMLElement>('.sheet-list')!;
    for (const protocol of server?.protocols ?? []) addChoice(list, protocolLabel(protocol.id), server?.label ?? '', protocol.id === peerDraft.protocol, () => {
      peerDraft.protocol = protocol.id;
      renderSharePanel();
      sheet.close();
    });
  });
}

function updatePeerFormState() {
  const validation = validatePeerDraft(peerDraft, serverTargets());
  const provisioning = validatePeerProvisioning(peerDraft, serverTargets());
  const submit = query<HTMLButtonElement>('#create-peer');
  submit.disabled = !validation.valid || !provisioning.valid;
  const message = !validation.valid && peerDraft.name.length > 0
    ? 'Проверьте имя (до 64 символов без управляющих знаков), сервер и доступный протокол.' : '';
  query('#peer-validation').textContent = t(message);
  query('#peer-name').setAttribute('aria-invalid', String(!validation.valid && peerDraft.name.length > 0));
  query('#peer-note').textContent = t('Имя и параметры можно подготовить. Создание пользователя требует доступа к управлению сервером; клиентский конфиг такого доступа не предоставляет.');
}

function openLanguageSheet() {
  openSheet('Язык приложения', container => {
    setSheetContent(container, '<div class="sheet-list language-options" role="radiogroup" aria-label="Язык приложения"></div>');
    const list = container.querySelector<HTMLElement>('.sheet-list')!;
    for (const [code, label] of [['ru', 'Русский'], ['en', 'English']] as const) {
      addChoice(list, label, '', getLanguage() === code, async () => {
        sheet.close();
        setLanguage(code);
        applyTranslations(app);
        render();
        if (currentScreen !== 'home') await showScreen(currentScreen, 'back');
      });
    }
  });
}

const implementationCopy: Record<ProtocolDescriptor['implementation'], string> = {
  import_and_storage: 'Импорт и защищённое хранение готовы',
  catalogued: 'Адаптер в разработке',
  desktop_research: 'Только desktop-исследование',
};

type ScreenKind = 'home' | 'share' | 'settings' | 'add' | 'server' | 'protocols' | 'application' | 'security' | 'backup';
type ShareTab = 'connection' | 'users';
let currentScreen: ScreenKind = 'home';
let screenHistory: ScreenKind[] = [];
let screenRevision = 0;
let shareTab: ShareTab = 'connection';

function renderSharePanel() {
  const panel = query<HTMLElement>('#share-panel');
  document.querySelectorAll<HTMLButtonElement>('[data-share-tab]').forEach((button) => {
    const selected = button.dataset.shareTab === shareTab;
    button.classList.toggle('selected', selected);
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  panel.setAttribute('aria-labelledby', `share-tab-${shareTab}`);
  if (shareTab === 'connection') {
    const { servers, server } = syncPeerDraft();
    panel.innerHTML = localizeStaticMarkup(`
      <p class="screen-lead">Отдельное подключение для пользователя без доступа к управлению сервером.</p>
      <form class="form-card peer-form" id="peer-form">
        <label><span>Имя пользователя</span><input id="peer-name" name="peerName" placeholder="Новый пользователь" maxlength="128" autocomplete="off" required></label>
        <div class="field-summary"><span>Сервер</span><button id="peer-server" class="select-field" type="button" aria-haspopup="dialog"><span data-current-profile></span>${icon('ChevronDown', 18)}</button></div>
        <div class="field-summary"><span>Протокол</span><button id="peer-protocol" class="select-field" type="button" aria-haspopup="dialog"><span data-current-protocol></span>${icon('ChevronDown', 18)}</button></div>
        <div class="field-summary"><span>Формат подключения</span><strong>Velum / совместимый .conf</strong></div>
        <p class="form-note" id="peer-validation" aria-live="polite"></p>
        <button class="primary-action" id="create-peer" type="submit" disabled>Создать пользователя</button>
      </form>
      <p class="screen-notice" id="peer-note" role="note"></p>`);
    const name = query<HTMLInputElement>('#peer-name');
    name.value = peerDraft.name;
    name.addEventListener('input', () => { peerDraft.name = name.value; updatePeerFormState(); });
    query<HTMLButtonElement>('#peer-server').disabled = servers.length <= 1;
    query('#peer-server').addEventListener('click', openPeerServers);
    query<HTMLButtonElement>('#peer-protocol').disabled = !server?.protocols.length;
    query('#peer-protocol').addEventListener('click', openPeerProtocols);
    panel.querySelector('[data-current-profile]')!.textContent = server?.label ?? t('Профиль не выбран');
    panel.querySelector('[data-current-protocol]')!.textContent = server ? protocolLabel(peerDraft.protocol) : t('Не выбран');
    query('#peer-form').addEventListener('submit', event => {
      event.preventDefault();
      updatePeerFormState();
      toast('Создание пользователя требует доступа к управлению сервером.', true);
    });
    updatePeerFormState();
  } else {
    panel.innerHTML = localizeStaticMarkup(`
      <div class="form-card">
        <div class="field-summary"><span>Сервер</span><strong data-current-profile></strong></div>
        <div class="field-summary"><span>Протокол</span><strong data-current-protocol></strong></div>
      </div>
      <div class="empty-state">
        <span class="empty-icon">${icon('Share2', 28)}</span>
        <h3>Пользователи</h3>
        <p>Список пользователей пока недоступен. Для просмотра, переименования и отзыва доступа требуется подключить управление сервером.</p>
      </div>
      <div class="screen-notice" role="note">Локальные профили не являются списком пользователей сервера. Существующие подключения здесь не изменяются.</div>`);
    const selected = storedProfiles.find((profile) => profile.name === profileName);
    panel.querySelector<HTMLElement>('[data-current-profile]')!.textContent = selected?.name ?? t('Профиль не выбран');
    panel.querySelector<HTMLElement>('[data-current-protocol]')!.textContent = selected ? protocolLabel(selected.protocol) : t('Не выбран');
  }
}

async function showScreen(kind: ScreenKind, navigation: 'push' | 'root' | 'back' = 'push') {
  if (sheet.isOpen()) sheet.close();
  if (navigation === 'root') screenHistory = kind === 'home' ? [] : ['home'];
  else if (navigation === 'push' && kind !== currentScreen) screenHistory.push(currentScreen);
  currentScreen = kind;
  const revision = ++screenRevision;
  const home = query<HTMLElement>('.home-view');
  const screen = query<HTMLElement>('#secondary-screen');
  query<HTMLElement>('.topbar').hidden = kind !== 'home';
  if (kind === 'home') {
    home.hidden = false;
    screen.hidden = true;
    query<HTMLButtonElement>('#power').focus({ preventScroll: true });
    return;
  }

  home.hidden = true;
  screen.hidden = false;
  const section = ['application', 'security', 'backup'].includes(kind)
    || (['server', 'protocols'].includes(kind) && screenHistory.includes('settings'))
    ? 'settings'
    : ['server', 'protocols'].includes(kind) ? 'add' : kind;
  document.querySelectorAll<HTMLButtonElement>('.screen-bottom-nav [data-screen]').forEach((button) => {
    if (button.dataset.screen === section) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  const title = query<HTMLElement>('#screen-title');
  const content = query<HTMLElement>('#screen-content');
  content.dataset.screen = kind;
  content.scrollTop = 0;

  if (kind === 'share') {
    title.textContent = t('Поделиться VPN');
    content.innerHTML = localizeStaticMarkup(`
      <div class="screen-tabs" role="tablist" aria-label="Раздел доступа">
        <button id="share-tab-connection" data-share-tab="connection" type="button" role="tab" aria-controls="share-panel">Соединение</button>
        <button id="share-tab-users" data-share-tab="users" type="button" role="tab" aria-controls="share-panel">Пользователи</button>
      </div>
      <section class="share-panel" id="share-panel" role="tabpanel" tabindex="0"></section>`);
    renderSharePanel();
    content.querySelector<HTMLElement>('.screen-tabs')!.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      shareTab = event.key === 'Home' ? 'connection' : event.key === 'End' ? 'users' : shareTab === 'connection' ? 'users' : 'connection';
      renderSharePanel();
      query<HTMLButtonElement>(`#share-tab-${shareTab}`).focus();
    });
  } else if (kind === 'settings') {
    title.textContent = t('Настройки');
    content.innerHTML = localizeStaticMarkup(`
      <div class="settings-list">
        <button data-screen="server" type="button"><span>${icon('Server', 20)}<b>Серверы</b></span>${icon('ChevronRight', 19)}</button>
        <button data-screen="protocols" type="button"><span>${icon('Wifi', 20)}<b>Протоколы и соединение</b></span>${icon('ChevronRight', 19)}</button>
        <button data-screen="application" type="button"><span>${icon('Gauge', 20)}<b>Приложение</b></span>${icon('ChevronRight', 19)}</button>
        <button data-screen="security" type="button"><span>${icon('ShieldCheck', 20)}<b>Безопасность и DNS</b></span>${icon('ChevronRight', 19)}</button>
        <button data-screen="backup" type="button"><span>${icon('Import', 20)}<b>Резервная копия</b></span>${icon('ChevronRight', 19)}</button>
        <div class="settings-audit"><strong>Локальное управление</strong><small>Настройки и состояние доступных функций — в каждом разделе.</small></div>
      </div>`);
  } else if (kind === 'application') {
    title.textContent = t('Приложение');
    content.innerHTML = localizeStaticMarkup(`
      <div class="detail-stack">
        <button class="field-summary language-trigger" data-action="language" type="button"><span>Язык приложения</span><strong data-language-value></strong></button>
        <article class="detail-card"><h3>Velum VPN</h3><p>Ваши профили и настройки подключения в одном приложении.</p>
          <div class="detail-list">
            <div class="detail-row"><span>Сборка</span><strong>Предварительная</strong></div>
            <div class="detail-row"><span>Оформление</span><strong>Тёмное</strong></div>
            <div class="detail-row"><span>Хранилище</span><strong data-storage-state></strong></div>
            <div class="detail-row"><span>Сетевой модуль</span><strong data-module-state></strong></div>
          </div>
        </article>
        <article class="detail-card"><h3>Ваши данные</h3><p>В приложении нет встроенной аналитики и автоматической отправки профилей. Импорт в Windows выполняется через системное окно выбора файла.</p></article>
        ${tauriRuntimeAvailable ? '<button class="inline-action" data-action="refresh-local" type="button">Обновить локальное состояние</button>' : '<div class="screen-notice" role="note">Это предпросмотр интерфейса в браузере. Локальное хранилище и системный модуль здесь недоступны.</div>'}
      </div>`);
    content.querySelector('[data-language-value]')!.textContent = getLanguage() === 'ru' ? 'Русский' : 'English';
    content.querySelector<HTMLElement>('[data-storage-state]')!.textContent = tauriRuntimeAvailable ? 'Windows DPAPI' : t('Недоступно в браузере');
    content.querySelector<HTMLElement>('[data-module-state]')!.textContent = t(status.backend_trusted ? 'Доверенный модуль найден' : 'Не установлен');
  } else if (kind === 'security') {
    title.textContent = t('Безопасность и DNS');
    content.innerHTML = localizeStaticMarkup(`
      <div class="detail-stack">
        <article class="detail-card"><h3>Защита профилей</h3><p>В Windows импортированные ключи зашифрованы с помощью DPAPI и привязаны к вашей учётной записи. Их содержимое не передаётся в интерфейс приложения.</p></article>
        <article class="detail-card"><h3>Защита трафика</h3><p>Защита при обрыве, DNS и IPv6 ещё не прошла испытания на Windows. Подключение заблокировано до проверки системного модуля. Запуск службы не подтверждает безопасность трафика.</p></article>
        <article class="detail-card"><h3>Диагностика службы</h3>
          <p>Локальная проверка не отправляет запросы в интернет и не меняет соединение. Рукопожатие и счётчики — не тест отсутствия утечек.</p>
          <button id="inspect-tunnel" class="inline-action" type="button">Проверить службу</button>
          <p id="inspection-result" role="status" data-dynamic></p>
        </article>
        <article class="detail-card"><h3>Маршруты и DNS</h3><p>Адрес VPN-сервера, DNS и исходные маршруты берутся из выбранного профиля. В настройках маршрутов можно выбрать сети CIDR; фактическая работа требует системного адаптера.</p>
          <button class="inline-action" data-action="open-routes" type="button">Открыть маршруты ${icon('ChevronRight', 18)}</button>
        </article>
        <div class="screen-notice" role="note">Velum использует один VPN-сервер. Многоузловой маршрутизации Tor и изоляции браузера здесь нет.</div>
      </div>`);
    const inspect = content.querySelector<HTMLButtonElement>('#inspect-tunnel')!;
    const result = content.querySelector<HTMLElement>('#inspection-result')!;
    inspect.disabled = !tauriRuntimeAvailable || !status.backend_trusted || !status.profile;
    result.textContent = t(inspect.disabled
      ? 'Проверка доступна при незавершённой VPN-операции и доверенном модуле.'
      : 'Состояние службы ещё не запрошено.');
    inspect.addEventListener('click', async () => {
      inspect.disabled = true;
      result.textContent = t('Проверка локальной службы…');
      try {
        const evidence = await invoke<BackendObservation>('inspect_tunnel');
        if (revision !== screenRevision) return;
        const serviceLabels: Record<BackendObservation['service_state'], string> = {
          absent: 'Служба отсутствует', stopped: 'Служба остановлена',
          start_pending: 'Служба запускается', running: 'Служба работает',
          stop_pending: 'Служба останавливается', unknown: 'Состояние службы неизвестно',
        };
        const summary = [t(serviceLabels[evidence.service_state])];
        if (evidence.uapi_state === 'available') {
          summary.push(t(evidence.handshake_fresh ? 'Недавнее рукопожатие есть' : 'Недавнего рукопожатия нет'));
          summary.push(`${t('Получено байт')}: ${evidence.rx_bytes} · ${t('Отправлено байт')}: ${evidence.tx_bytes}`);
        } else summary.push(t('Статистика туннеля недоступна'));
        summary.push(`${t('Время проверки')}: ${new Date(evidence.observed_at_unix_seconds * 1000).toLocaleTimeString(getLanguage() === 'ru' ? 'ru-RU' : 'en-GB')}`);
        summary.push(t('Защита трафика не подтверждена.'));
        result.textContent = summary.join(' · ');
      } catch {
        if (revision === screenRevision) result.textContent = t('Состояние не подтверждено: служба недоступна или её ответ отклонён.');
      } finally {
        if (revision === screenRevision) inspect.disabled = !status.profile || !status.backend_trusted;
      }
    });
  } else if (kind === 'backup') {
    title.textContent = t('Резервная копия');
    content.innerHTML = localizeStaticMarkup(`
      <div class="detail-stack">
        <article class="detail-card"><h3>Сохраните исходный профиль</h3><p>Храните полученный .conf или .vpn в защищённом месте. В нём могут находиться приватные ключи — не публикуйте его и не отправляйте посторонним.</p></article>
        <article class="detail-card"><h3>Перенос на другое устройство</h3><p>Зашифрованное хранилище DPAPI привязано к пользователю Windows. Простое копирование файлов хранилища не заменяет переносимый архив.</p></article>
        <div class="screen-notice" role="note">Создание и восстановление переносимого архива ещё недоступны. Сейчас можно импортировать исходный файл подключения; существующий профиль не будет перезаписан.</div>
        <button class="inline-action" data-action="import" type="button">Импортировать профиль ${icon('Import', 18)}</button>
      </div>`);
  } else if (kind === 'add') {
    title.textContent = t('Соединение');
    content.innerHTML = localizeStaticMarkup(`
      <p class="screen-lead">Добавьте готовый профиль VPN или узнайте о подключении собственного сервера.</p>
      <div class="key-paste"><input aria-label="Ключ подключения" placeholder="Ключ подключения" autocomplete="off" spellcheck="false" disabled><button type="button" disabled>Вставить</button></div>
      <p class="form-note">Вставка ключа и QR-код пока недоступны. Файл .conf или .vpn можно импортировать ниже.</p>
      <small class="section-label">ДРУГИЕ ВАРИАНТЫ</small>
      <div class="connection-options">
        <button data-screen="server" type="button"><span>${icon('Server', 22)}</span><span><b>Self-hosted VPN</b><small>Подключение собственного сервера</small></span>${icon('ChevronRight', 20)}</button>
        <button data-action="import" type="button"><span>${icon('Import', 22)}</span><span><b>Файл подключения</b><small>Импорт .conf или .vpn в Windows</small></span>${icon('ChevronRight', 20)}</button>
        <button data-screen="protocols" type="button"><span>${icon('Layers3', 22)}</span><span><b>Каталог протоколов</b><small>Доступность и поддержка</small></span>${icon('ChevronRight', 20)}</button>
      </div>`);
  } else if (kind === 'server') {
    title.textContent = t('Свой сервер');
    content.innerHTML = localizeStaticMarkup(`
      <div class="detail-stack">
        <p class="screen-lead">Используйте профиль VPN с собственного сервера.</p>
        <article class="detail-card"><h3>Сервер уже настроен</h3><p>Импортируйте совместимый .conf или файл подключения .vpn. Для добавления такого профиля SSH-доступ не нужен.</p>
          <button class="inline-action" data-action="import" type="button">Добавить файл ${icon('Import', 18)}</button>
        </article>
        <article class="detail-card"><h3>Развёртывание в Docker</h3><p>Серверная часть Velum использует отдельный Docker Compose-проект. Управление развёртыванием через приложение ещё не подключено.</p></article>
        <div class="screen-notice" role="note">SSH-подключение из этого окна пока недоступно. Приложение не запрашивает пароль сервера и не выполняет удалённые команды.</div>
      </div>`);
  } else {
    title.textContent = t('Протоколы');
    content.innerHTML = localizeStaticMarkup('<div class="protocol-list"><p class="screen-lead">Загрузка локального каталога…</p></div>');
    if (!tauriRuntimeAvailable) {
      content.innerHTML = localizeStaticMarkup('<div class="screen-notice" role="note">Каталог системных адаптеров доступен в приложении Velum. В браузере показан только интерфейс, подключение VPN здесь недоступно.</div>');
      window.requestAnimationFrame(() => title.focus({ preventScroll: true }));
      return;
    }
    try {
      const protocols = await invoke<ProtocolDescriptor[]>('list_protocols');
      if (revision !== screenRevision) return;
      const list = query<HTMLElement>('.protocol-list');
      list.replaceChildren();
      protocols.forEach((protocol) => {
        const card = document.createElement('article');
        card.className = `protocol-card state-${protocol.implementation}`;
        const track = `${t('Цель после реализации:')} ${protocol.target_release_track === 'general_availability' ? 'GA' : protocol.target_release_track}`;
        card.innerHTML = `<div><strong></strong><span></span></div><p></p><small></small>`;
        card.querySelector('strong')!.textContent = protocol.name;
        card.querySelector('span')!.textContent = track;
        card.querySelector('p')!.textContent = t(protocol.summary);
        card.querySelector('small')!.textContent = `${t(implementationCopy[protocol.implementation])} · ${t('Целевые ОС:')} ${protocol.target_platforms.join(' · ')}`;
        list.append(card);
      });
    } catch {
      if (revision !== screenRevision) return;
      content.textContent = t('Не удалось загрузить локальный каталог протоколов. Вернитесь в настройки и повторите попытку.');
    }
  }

  window.requestAnimationFrame(() => {
    if (revision === screenRevision) title.focus({ preventScroll: true });
  });
}

query<HTMLElement>('#screen-content').addEventListener('click', async (event) => {
  const button = (event.target as Element).closest<HTMLButtonElement>('button');
  if (!button || button.disabled) return;
  if (button.dataset.shareTab) {
    shareTab = button.dataset.shareTab as ShareTab;
    renderSharePanel();
  } else if (button.dataset.screen) {
    await showScreen(button.dataset.screen as ScreenKind);
  } else if (button.dataset.action === 'import') {
    await importProfile();
  } else if (button.dataset.action === 'open-routes') {
    await showScreen('home', 'root');
    toggleRoutes(true);
  } else if (button.dataset.action === 'language') {
    openLanguageSheet();
  } else if (button.dataset.action === 'refresh-local') {
    button.disabled = true;
    await refresh();
    await loadStoredProfiles();
    if (currentScreen === 'application') await showScreen('application', 'back');
  }
});

document.querySelectorAll<HTMLButtonElement>('[data-action="import"]').forEach((button) => {
  button.addEventListener('click', importProfile);
});
document.querySelectorAll<HTMLButtonElement>('[data-action="routes"]').forEach((button) => {
  button.addEventListener('click', () => toggleRoutes());
});
query<HTMLButtonElement>('#split-shortcut').addEventListener('click', () => toggleRoutes());
query<HTMLButtonElement>('#profile-select').addEventListener('click', openServerSheet);

let importActive = false;
async function importProfile() {
  if (!tauriRuntimeAvailable) {
    toast('Нативный импорт конфигурации доступен в приложении Velum для Windows.', true);
    return;
  }
  if (importActive) return;
  importActive = true;
  try {
    const stored = await invoke<StoredProfile | null>('import_profile_file');
    if (!stored) return;
    await loadStoredProfiles(stored.name);
    toast(t('Профиль сохранён локально'));
  } catch {
    toast('Профиль отклонён. Проверьте формат файла и отсутствие профиля с таким именем.', true);
  } finally {
    importActive = false;
  }
}

document.querySelectorAll<HTMLButtonElement>('[data-policy]').forEach((button) => {
  button.addEventListener('click', () => {
    if (status.profile || status.state === 'connecting' || status.state === 'disconnecting') return;
    policy = button.dataset.policy!;
    document.querySelectorAll<HTMLButtonElement>('[data-policy]').forEach((candidate) => {
      const selected = candidate === button;
      candidate.classList.toggle('selected', selected);
      candidate.setAttribute('aria-pressed', String(selected));
    });
    const input = query<HTMLInputElement>('#networks');
    input.disabled = policy === 'profile_routes';
    renderPolicy();
  });
});

query<HTMLButtonElement>('#power').addEventListener('click', async () => {
  if (status.profile) {
    try {
      status.state = 'disconnecting';
      render();
      await invoke('disconnect_tunnel');
      await refresh();
      toast('Туннель отключён');
    } catch {
      await refresh();
      toast('Не удалось отключить туннель. Состояние соединения не подтверждено.', true);
    }
    return;
  }
  if (!profileName) {
    await importProfile();
    return;
  }
  if (appRulesBlockConnect()) {
    toast('Правила приложений не подтверждены. Подключение заблокировано.', true);
    return;
  }
  if (!status.backend_trusted) {
    toast('Подключение заблокировано: подписанный и закреплённый модуль Velum ещё не установлен.', true);
    return;
  }
  status.state = 'connecting';
  render();
  try {
    const networks = policy === 'only_selected'
      ? query<HTMLInputElement>('#networks').value.split(',').map((value) => value.trim()).filter(Boolean)
      : [];
    await invoke('connect_tunnel', {
      name: profileName,
      policy: { mode: policy, networks, domains: [], applications: [], bypass_lan: false },
    });
    await refresh();
    toast('Системная служба приняла конфигурацию. Диагностика доступна в настройках безопасности; защита трафика пока не подтверждена.');
  } catch {
    await refresh();
    status.state = 'error';
    status.message = 'Не удалось запустить туннель. Проверьте профиль и системный модуль.';
    render();
    toast(status.message, true);
  }
});

document.querySelectorAll<HTMLButtonElement>('[data-action="protocols"]').forEach((button) => button.addEventListener('click', () => showScreen('protocols')));
document.querySelectorAll<HTMLButtonElement>('[data-action="server"]').forEach((button) => button.addEventListener('click', () => showScreen('server')));
document.querySelectorAll<HTMLButtonElement>('[data-action="share"]').forEach((button) => button.addEventListener('click', () => showScreen('share')));
document.querySelectorAll<HTMLButtonElement>('[data-action="settings"]').forEach((button) => button.addEventListener('click', () => showScreen('settings')));
document.querySelectorAll<HTMLButtonElement>('[data-action="add"]').forEach((button) => button.addEventListener('click', () => showScreen('add')));
document.querySelectorAll<HTMLButtonElement>('[data-action="home"]').forEach((button) => button.addEventListener('click', () => showScreen('home', 'root')));
query<HTMLButtonElement>('#screen-back').addEventListener('click', () => showScreen(screenHistory.pop() ?? 'home', 'back'));
document.querySelectorAll<HTMLButtonElement>('.screen-bottom-nav [data-screen]').forEach((button) => {
  button.addEventListener('click', () => showScreen(button.dataset.screen as ScreenKind, 'root'));
});

Promise.all([refresh().then(() => loadStoredProfiles()), loadApplicationRules()]);
