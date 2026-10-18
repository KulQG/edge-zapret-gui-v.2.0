import './style.css'
import { listen } from '@tauri-apps/api/event'
import defaultBackground from './assets/default/alt-lineup.png'
import powerIcon from './assets/icons/power.svg?raw'
import refreshIcon from './assets/icons/refresh-cw.svg?raw'
import rollbackIcon from './assets/icons/rotate-ccw.svg?raw'
import terminalIcon from './assets/icons/terminal.svg?raw'
import chevronIcon from './assets/icons/chevron-down.svg?raw'
import imageIcon from './assets/icons/image.svg?raw'
import saveIcon from './assets/icons/save.svg?raw'
import closeIcon from './assets/icons/x.svg?raw'
import alertIcon from './assets/icons/circle-alert.svg?raw'
import checkIcon from './assets/icons/circle-check.svg?raw'
import { cancelStrategyScan, checkCurrentStrategy, getConfig, getDiagnostics, getManualStatus, getRollbackAvailable, getStrategies, getStrategyScanState, importAppearanceAsset, openServiceConsole, readAppearanceAsset, recoverStrategyScan, rollbackEngine, saveAppearance, selectStrategy, startManual, startStrategyScan, stopManual, toAppError, updateEngine } from './bridge'
import type { AppearanceSettings, AppConfig, AppError, DiagnosticsSnapshot, EngineUpdateProgress, ManualSnapshot, ScanCheck, ScanProgress, ScanScope, ScanStrategyResult, StrategyInfo } from './bridge'

type PageId = 'home' | 'tests' | 'appearance'
let currentPage: PageId = 'home'
let diagnostics: DiagnosticsSnapshot | null = null
let diagnosticsError: AppError | null = null
let config: AppConfig | null = null
let configError: AppError | null = null
let configLoading = false
let appearanceDraft: AppearanceSettings | null = null
let appearanceBusy = false
let appearanceMessage: string | null = null
let appearanceError: AppError | null = null
let appearanceAssetError: string | null = null
let appearanceAssetUrls = new Map<string, string>()
let appearanceAssetLoads = new Map<string, Promise<string>>()
let appearanceLoadSequence = 0
let backgroundPreviewUrl: string | null = null
let strategies: StrategyInfo[] | null = null
let strategiesError: AppError | null = null
let selectedStrategyId: string | null = null
let manualSnapshot: ManualSnapshot | null = null
let manualStatusError: AppError | null = null
let manualBusy = false
let manualPolling = false
let manualPollTimer: number | null = null
let manualActionError: AppError | null = null
let serviceConsoleError: AppError | null = null
let serviceConsoleBusy = false
let updateBusy = false
let updateError: AppError | null = null
let updateProgress: EngineUpdateProgress | null = null
let updateFinished: string | null = null
let updateCleanupWarning: AppError | null = null
let rollbackAvailable = false
let deferredHomeRender = false
let scanScope: ScanScope = 'both'
let scanAllStrategies = true
let scanSelectedIds = new Set<string>()
let scanFastMode = false
let scanProgress: ScanProgress | null = null
let scanBusy = false
let scanCancelBusy = false
let scanCancelRequested = false
let scanCurrentBusy = false
let scanRecoveryPending = false
let scanRecoverBusy = false
let scanOperationId: string | null = null
let scanError: AppError | null = null
let currentCheckResult: ScanStrategyResult | null = null
const expandedScanResults = new Set<string>()
let scanBackendSeen = false
let scanStartedAt = 0
let scanStatePolling = false

const icons = { power: powerIcon, refresh: refreshIcon, rollback: rollbackIcon, terminal: terminalIcon, chevron: chevronIcon, image: imageIcon, save: saveIcon, close: closeIcon, alert: alertIcon, check: checkIcon }

function icon(name: keyof typeof icons): string {
  return icons[name].replace('<svg', '<svg class="ui-icon" aria-hidden="true" focusable="false"')
}

function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] ?? character)
}

const defaultAppearance: AppearanceSettings = {
  backgroundAsset: null,
  mascotAsset: null,
  backgroundOpacity: 85,
  backgroundBlur: 0,
  backgroundPositionX: 50,
  backgroundPositionY: 100,
  backgroundScale: 100,
  backgroundFit: 'contain',
  mascotScale: 100,
  mascotPositionX: 50,
  mascotPositionY: 50,
  mascotOpacity: 100,
  darkOverlay: 10
}

function cloneAppearance(settings: AppearanceSettings): AppearanceSettings {
  return { ...settings }
}

function appearanceIsDirty(): boolean {
  if (!config || !appearanceDraft) return false
  return JSON.stringify(appearanceDraft) !== JSON.stringify(config.appearance)
}

function appearanceMime(assetId: string): string {
  const extension = assetId.split('.').at(-1)?.toLowerCase()
  return extension === 'png' ? 'image/png' : extension === 'webp' ? 'image/webp' : 'image/jpeg'
}

async function getAppearanceAssetUrl(assetId: string): Promise<string> {
  const cached = appearanceAssetUrls.get(assetId)
  if (cached) return cached
  const pending = appearanceAssetLoads.get(assetId)
  if (pending) return pending
  const request = readAppearanceAsset(assetId).then((bytes) => {
    const url = URL.createObjectURL(new Blob([bytes], { type: appearanceMime(assetId) }))
    appearanceAssetUrls.set(assetId, url)
    return url
  }).finally(() => appearanceAssetLoads.delete(assetId))
  appearanceAssetLoads.set(assetId, request)
  return request
}

function revokeUnusedAppearanceUrls(): void {
  const retained = new Set([config?.appearance.backgroundAsset, config?.appearance.mascotAsset, appearanceDraft?.backgroundAsset, appearanceDraft?.mascotAsset].filter((id): id is string => !!id))
  for (const [assetId, url] of appearanceAssetUrls) {
    if (retained.has(assetId)) continue
    URL.revokeObjectURL(url)
    appearanceAssetUrls.delete(assetId)
  }
}

function applyAppearancePreview(backgroundUrl = backgroundPreviewUrl): void {
  const settings = appearanceDraft ?? config?.appearance ?? defaultAppearance
  const root = document.documentElement.style
  const imageUrl = backgroundUrl ?? defaultBackground
  root.setProperty('--appearance-bg-url', `url("${imageUrl}")`)
  root.setProperty('--appearance-bg-opacity', String(settings.backgroundOpacity / 100))
  root.setProperty('--appearance-bg-blur', `${settings.backgroundBlur}px`)
  root.setProperty('--appearance-bg-position', `50% ${settings.backgroundPositionY}%`)
  root.setProperty('--appearance-bg-pan-x', `${(settings.backgroundPositionX - 50) / 2}%`)
  root.setProperty('--appearance-bg-scale', String(settings.backgroundScale / 100))
  root.setProperty('--appearance-bg-fit', settings.backgroundFit)
  root.setProperty('--appearance-dark-overlay', String(settings.darkOverlay / 100))
  document.querySelectorAll<HTMLElement>('.appearance-preview').forEach((preview) => {
    preview.style.setProperty('--preview-bg-url', `url("${imageUrl}")`)
  })
}

async function loadAppearanceAssets(settings: AppearanceSettings): Promise<void> {
  const sequence = ++appearanceLoadSequence
  const backgroundPromise = settings.backgroundAsset
    ? getAppearanceAssetUrl(settings.backgroundAsset).then((url) => ({ url, error: null as string | null })).catch((error) => ({ url: null, error: toAppError(error).message }))
    : Promise.resolve({ url: null, error: null as string | null })
  const backgroundResult = await backgroundPromise
  if (sequence !== appearanceLoadSequence) return
  backgroundPreviewUrl = backgroundResult.url
  appearanceAssetError = backgroundResult.error
  applyAppearancePreview(backgroundPreviewUrl)
  revokeUnusedAppearanceUrls()
  updateAppearanceAssetErrorUi()
}

function updateAppearanceAssetErrorUi(): void {
  const background = content?.querySelector<HTMLElement>('#appearance-background-error')
  if (background) {
    background.hidden = !appearanceAssetError
    background.textContent = appearanceAssetError
      ? `Не удалось открыть сохранённый фон: ${appearanceAssetError} Настройки не изменены; проверьте журнал или выберите файл повторно.`
      : ''
  }
}

function errorMarkup(error: AppError): string {
  return `<div class="data-error" role="alert"><strong>${escapeHtml(error.message)}</strong>${error.detail ? `<details><summary>Подробности</summary><p>${escapeHtml(error.detail)}</p></details>` : ''}${error.action ? `<p>${escapeHtml(error.action)}</p>` : ''}</div>`
}

function help(text: string): string {
  return `<span class="help-tip" tabindex="0" role="note" aria-label="Справка: ${escapeHtml(text)}" title="${escapeHtml(text)}">?</span>`
}

function strategyById(id: string | null | undefined): StrategyInfo | undefined {
  return strategies?.find((strategy) => strategy.id === id)
}

function altStrategies(): StrategyInfo[] {
  return strategies?.filter((item) => item.supported && /\bALT\d*\b/i.test(item.id)) ?? []
}

function manualConflict(): string | null {
  if (!diagnostics) return diagnosticsError?.message ?? 'Проверяем состояние движка…'
  if (!diagnostics.engine.ready) return diagnostics.engine.issue ?? 'Установите zapret через кнопку «Обновить».'
  if (diagnostics.service.state === 'running') return 'Служба zapret уже работает. Управляйте ею через официальный service.bat.'
  if (['pending', 'unknown', 'error'].includes(diagnostics.service.state)) return 'Не удалось проверить службу zapret. Повторите попытку позже.'
  if (diagnostics.winDivert.state === 'running' && !diagnostics.winDivert.managed) return 'Обнаружен сторонний WinDivert. Запуск заблокирован.'
  if (diagnostics.winDivert.error || ['pending', 'unknown', 'error'].includes(diagnostics.winDivert.state)) return 'Не удалось проверить WinDivert. Запуск заблокирован.'
  const ownPid = manualSnapshot?.status.running ? manualSnapshot.status.pid : null
  if (diagnostics.processes.some((process) => process.pid !== ownPid)) return 'Обнаружен другой winws.exe. Приложение не будет его останавливать.'
  return null
}

const app = document.querySelector<HTMLDivElement>('#app')
if (!app) throw new Error('Application root is missing')
app.innerHTML = `<div class="app-shell">
  <header class="topbar">
    <nav class="nav-list" aria-label="Разделы приложения"><button class="nav-item active" type="button" data-page="home" aria-current="page">Главная</button><button class="nav-item" type="button" data-page="tests" aria-current="false">Тесты ALT</button><button class="nav-item" type="button" data-page="appearance" aria-current="false">Оформление</button></nav>
  </header>
  <main class="main-panel"><div id="page-content" class="page-content"></div></main>
</div>`
const content = document.querySelector<HTMLDivElement>('#page-content')
if (!content) throw new Error('Application layout is incomplete')

function renderHome(): string {
  const status = manualSnapshot?.status
  const running = status?.running === true && status.state === 'running'
  const selected = strategyById(selectedStrategyId)
  const conflict = running ? null : manualConflict()
  const strategyChoices = strategies?.filter((item) => item.supported) ?? []
  const lampState = running ? 'on' : manualStatusError || !status ? 'unknown' : 'off'
  const lampLabel = running ? 'Включено' : lampState === 'off' ? 'Выключено' : 'Состояние неизвестно'
  const updateDisabled = updateBusy || manualBusy || scanBusy || scanCurrentBusy || !!diagnostics?.service.installed
  const updateTitle = diagnostics?.service.installed ? 'При установленной службе обновление недоступно. Откройте консоль.' : ''
  const progressLabels: Record<EngineUpdateProgress['stage'], string> = { download: 'Загрузка…', validate: 'Проверка…', stopService: 'Остановка службы…', stopManual: 'Остановка…', stopWinDivert: 'Остановка драйвера…', replace: 'Установка…', restore: 'Восстановление…', complete: 'Готово' }
  const notice = updateError ? { tone: 'error', label: updateError.message, detail: updateError.action ?? updateError.detail }
    : updateCleanupWarning ? { tone: 'warning', label: 'Обновлено с предупреждением', detail: updateCleanupWarning.message }
    : updateBusy && updateProgress ? { tone: 'progress', label: progressLabels[updateProgress.stage], detail: updateProgress.message }
    : updateFinished ? { tone: 'success', label: updateFinished, detail: null }
    : null
  return `<section class="minimal-home">
    <div class="app-wordmark"><h1>ZAPRET</h1></div>
    <div class="home-main">
      <div class="home-controls">
        <div class="strategy-heading"><label for="strategy-select">Стратегия</label><span class="power-lamp is-${lampState}" role="status" aria-label="${lampLabel}" title="${lampLabel}"></span></div>
        <div class="control-row"><div class="strategy-select-wrap"><select id="strategy-select" ${manualBusy || updateBusy || scanBusy || scanCurrentBusy || running || !strategyChoices.length ? 'disabled' : ''}>${strategyChoices.length ? `<option value="" ${!selected?.supported ? 'selected' : ''} disabled>Выберите стратегию</option>${strategyChoices.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === selectedStrategyId ? 'selected' : ''}>${escapeHtml(item.displayName)}</option>`).join('')}` : '<option value="">Стратегии недоступны</option>'}</select><span class="select-chevron">${icon('chevron')}</span></div>
          <button class="action-button ${running ? 'danger-button' : 'primary-button'}" type="button" data-manual-action="${running ? 'stop' : 'start'}" ${manualBusy || updateBusy || scanBusy || scanCurrentBusy || (!running && (!selected?.supported || !!conflict)) ? 'disabled' : ''}>${icon('power')}<span>${manualBusy ? 'Подождите…' : running ? 'Остановить' : 'Запустить'}</span></button>
          <button class="action-button icon-button update-action" id="update-engine" type="button" title="${escapeHtml(updateTitle || (diagnostics?.engine.installed ? 'Обновить' : 'Установить'))}" aria-label="${diagnostics?.engine.installed ? 'Обновить' : 'Установить'}" ${updateDisabled ? 'disabled' : ''}>${icon('refresh')}</button>
        </div>
        <div class="secondary-actions">${rollbackAvailable ? `<button class="quiet-button" id="rollback-engine" type="button" ${updateDisabled ? 'disabled' : ''}>${icon('rollback')}<span>Откат</span></button>` : ''}<button class="quiet-button" id="open-service-console" type="button" title="Открыть официальный service.bat с запросом UAC" ${serviceConsoleBusy || updateBusy || manualBusy || scanBusy || scanCurrentBusy ? 'disabled' : ''}>${icon('terminal')}<span>Консоль</span></button></div>
        ${conflict ? `<p class="inline-warning" role="status">${escapeHtml(conflict)}</p>` : ''}${strategiesError ? errorMarkup(strategiesError) : ''}${manualStatusError ? errorMarkup(manualStatusError) : ''}${manualActionError ? errorMarkup(manualActionError) : ''}${serviceConsoleError ? errorMarkup(serviceConsoleError) : ''}
      </div>
    </div>
    ${notice ? `<div class="status-toast is-${notice.tone}" role="${notice.tone === 'error' ? 'alert' : 'status'}" title="${escapeHtml(notice.detail ?? notice.label)}">${icon(notice.tone === 'error' || notice.tone === 'warning' ? 'alert' : notice.tone === 'success' ? 'check' : 'refresh')}<span>${escapeHtml(notice.label)}</span></div>` : ''}
  </section>`
}

function appearanceRange(
  key: keyof AppearanceSettings,
  label: string,
  min: number,
  max: number,
  unit = '',
  description: string
): string {
  const value = Number(appearanceDraft?.[key] ?? defaultAppearance[key])
  return `<label class="appearance-range"><span class="appearance-range-heading"><span>${label} ${help(description)}</span><strong data-appearance-value="${key}">${value}${unit}</strong></span><input type="range" min="${min}" max="${max}" step="1" value="${value}" data-appearance-range="${key}" aria-label="${label}" title="${escapeHtml(description)}" /></label>`
}

function backgroundNeedsReset(draft: AppearanceSettings): boolean {
  return !!draft.backgroundAsset
    || draft.backgroundOpacity !== defaultAppearance.backgroundOpacity
    || draft.backgroundBlur !== defaultAppearance.backgroundBlur
    || draft.backgroundPositionX !== defaultAppearance.backgroundPositionX
    || draft.backgroundPositionY !== defaultAppearance.backgroundPositionY
    || draft.backgroundScale !== defaultAppearance.backgroundScale
    || draft.backgroundFit !== defaultAppearance.backgroundFit
    || draft.darkOverlay !== defaultAppearance.darkOverlay
}

function syncAppearanceActionButtons(): void {
  if (!appearanceDraft) return
  const background = content?.querySelector<HTMLButtonElement>('[data-appearance-action="reset-background"]')
  const save = content?.querySelector<HTMLButtonElement>('[data-appearance-action="save"]')
  const cancel = content?.querySelector<HTMLButtonElement>('[data-appearance-action="cancel"]')
  if (background) background.disabled = appearanceBusy || !backgroundNeedsReset(appearanceDraft)
  if (save) save.disabled = appearanceBusy || !appearanceIsDirty()
  if (cancel) cancel.disabled = appearanceBusy || !appearanceIsDirty()
}

function renderAppearance(): string {
  if (!config || !appearanceDraft) {
    return `<section class="subpage appearance-page"><div class="subpage-hero"><h2>Оформление</h2></div>${configError ? errorMarkup(configError) : '<div class="loading-card">Загружаем настройки…</div>'}</section>`
  }
  const draft = appearanceDraft
  const dirty = appearanceIsDirty()
  const backgroundName = draft.backgroundAsset ? 'Своё изображение' : 'Базовое изображение'
  const backgroundStatus = appearanceAssetError
    ? `Не удалось открыть сохранённый фон: ${escapeHtml(appearanceAssetError)} Настройки не изменены; проверьте журнал или выберите файл повторно.`
    : ''
  return `<section class="subpage appearance-page">
    <div class="subpage-hero"><h2>Фон</h2><span class="appearance-local-note">Изображение хранится на этом компьютере</span></div>
    ${appearanceError ? errorMarkup(appearanceError) : ''}
    <div class="appearance-layout">
      <article class="diagnostic-card appearance-preview-card"><div class="diagnostic-card-title"><h2>Предпросмотр</h2>${help('Фон главного экрана. Изменения видны до сохранения.')}</div>
        <div class="appearance-preview"><div class="appearance-preview-overlay"></div><div class="appearance-preview-copy"><strong>ZAPRET</strong></div><div class="appearance-preview-controls" aria-hidden="true"><span></span><div><i></i><i></i><i></i></div></div></div>
        <div class="appearance-preview-status"><div><span>Изображение</span><strong>${escapeHtml(backgroundName)}</strong></div></div><p id="appearance-background-error" class="appearance-asset-error" role="alert" ${backgroundStatus ? '' : 'hidden'}>${backgroundStatus}</p>
      </article>
      <div class="appearance-settings">
      <article class="diagnostic-card appearance-assets-card"><div class="diagnostic-card-title"><h2>Изображение</h2>${help('Выбранный фон копируется в локальные данные приложения. Сохраните оформление, чтобы закрепить изменение.')}</div>
        <div class="appearance-file-field"><button class="action-button" type="button" data-appearance-choose="background" ${appearanceBusy ? 'disabled' : ''}>${icon('image')}<span>Выбрать фон</span></button><input hidden type="file" accept="image/png,image/jpeg,image/webp,.png,.jpg,.jpeg,.webp" data-appearance-file="background" /></div>
        <button class="text-action-button" type="button" data-appearance-action="reset-background" ${appearanceBusy || !backgroundNeedsReset(draft) ? 'disabled' : ''}>${icon('rollback')}<span>Вернуть базовый фон</span></button>
        <p class="diagnostic-note appearance-limits">PNG, JPEG или WebP · до 8 МиБ.</p>
      </article>
      <div class="appearance-controls-grid">
      <article class="diagnostic-card"><div class="diagnostic-card-title"><h2>Настройки фона</h2>${help('Масштаб и положение меняют композицию; прозрачность, размытие и затемнение помогают читать интерфейс.')}</div>
        ${appearanceRange('backgroundScale', 'Размер фона', 50, 200, '%', 'Увеличьте фон для приближения или уменьшите его, чтобы оставить больше свободного места.')}
        ${appearanceRange('backgroundPositionX', 'По горизонтали', 0, 100, '%', 'Перемещает изображение влево или вправо, в том числе при исходном размере.')}
        ${appearanceRange('backgroundPositionY', 'По вертикали', 0, 100, '%', 'Выбирает положение изображения от верхнего до нижнего края.')}
        ${appearanceRange('backgroundOpacity', 'Прозрачность фона', 0, 100, '%', '0% скрывает изображение, 100% показывает его полностью.')}
        ${appearanceRange('backgroundBlur', 'Размытие фона', 0, 30, ' px', 'Размытие смягчает фон, чтобы текст и кнопки были заметнее.')}
        ${appearanceRange('darkOverlay', 'Тёмное затемнение', 0, 90, '%', 'Увеличьте затемнение, если светлый фон мешает читать интерфейс.')}
        <label class="appearance-select-field"><span>Заполнение ${help('«Заполнить» занимает всю доступную область и может обрезать края. «Вписать» показывает изображение целиком, оставляя свободные поля.')}</span><select data-appearance-fit><option value="cover" ${draft.backgroundFit === 'cover' ? 'selected' : ''}>Заполнить область</option><option value="contain" ${draft.backgroundFit === 'contain' ? 'selected' : ''}>Вписать целиком</option></select></label>
      </article>
      </div>
      <div class="appearance-save-row"><span class="appearance-dirty" role="status">${dirty ? 'Есть изменения' : appearanceMessage ?? 'Сохранено'}</span><div><button class="action-button" type="button" data-appearance-action="cancel" ${appearanceBusy || !dirty ? 'disabled' : ''}>${icon('close')}<span>Отмена</span></button><button class="action-button primary-button" type="button" data-appearance-action="save" ${appearanceBusy || !dirty ? 'disabled' : ''}>${icon('save')}<span>${appearanceBusy ? 'Сохраняем…' : 'Сохранить'}</span></button></div></div>
      </div>
    </div>
  </section>`
}

const scanServiceNames: Record<ScanCheck['category'], string> = { youtube: 'YouTube', discord: 'Discord', google: 'Google', cloudflare: 'Cloudflare' }
const scanVariantNames: Record<ScanCheck['variant'], string> = { http11: 'HTTP/1.1', tls12: 'TLS 1.2', tls13: 'TLS 1.3' }
const scanStatusNames: Record<ScanCheck['status'], string> = { passed: 'Ответ', failed: 'Ошибка', unsupported: 'Нет поддержки', skipped: 'Пропущено' }
const scanVerdictNames: Record<ScanStrategyResult['verdict'], string> = { passed: 'Все цели доступны', failed: 'Есть ошибки', incomplete: 'Не завершён', unsupported: 'Недоступно' }
const scanPhaseNames: Record<ScanProgress['phase'], string> = { preparing: 'Подготовка', testing: 'Проверка', restoring: 'Восстановление стратегии', completed: 'Завершено', cancelled: 'Остановлено', failed: 'Ошибка' }
const scanRestorationNames: Record<ScanProgress['restoration'], string> = { none: '', pending: 'Восстановление ожидается', restored: 'Исходное состояние восстановлено', failed: 'Восстановление не удалось' }
const scanGroups = ['youtube', 'discord', 'google', 'cloudflare'] as const
// Keep these counts aligned with the fixed endpoint list in strategy_probe.rs.
const scanExpectedChecks: Record<ScanCheck['category'], number> = { youtube: 9, discord: 12, google: 6, cloudflare: 6 }

function scanDuration(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) return ''
  return ms < 1000 ? `${Math.round(ms)} мс` : `${(ms / 1000).toFixed(2)} с`
}

function scanServiceSummary(result: ScanStrategyResult, service: ScanCheck['category']): string {
  const checks = result.checks.filter((check) => check.category === service)
  const expected = scanExpectedChecks[service]
  const state = checks.some((check) => check.status === 'failed') ? 'failed'
    : checks.some((check) => check.status === 'unsupported') ? 'unsupported'
      : checks.length === expected && checks.every((check) => check.status === 'passed') ? 'passed' : 'pending'
  const successfulTimes = checks.filter((check) => check.status === 'passed' && check.durationMs !== null).map((check) => check.durationMs!)
  const average = state === 'passed' && successfulTimes.length ? scanDuration(successfulTimes.reduce((sum, time) => sum + time, 0) / successfulTimes.length) : ''
  const description = state === 'passed' ? `все ${expected} проверок пройдены, среднее время ${average}`
    : state === 'failed' ? 'есть ошибка'
      : state === 'unsupported' ? 'вариант не поддерживается'
        : checks.length ? `выполнено ${checks.length} из ${expected}` : 'нет результатов'
  return `<span class="scan-service-summary is-${state}" role="img" aria-label="${scanServiceNames[service]}: ${escapeHtml(description)}"><span class="scan-service-name">${scanServiceNames[service]}</span><span class="scan-service-dot" aria-hidden="true"></span><span class="scan-service-value">${average || (state === 'pending' && checks.length ? `${checks.length}/${expected}` : '')}</span></span>`
}

function scanResultRow(result: ScanStrategyResult, heading?: string): string {
  const key = `${heading ?? 'scan'}:${result.strategyId}`
  const expanded = expandedScanResults.has(key)
  const version = `${result.checks.length}:${result.verdict}:${expanded}`
  const rows = scanGroups.map((service) => {
    const checks = result.checks.filter((check) => check.category === service)
    if (!checks.length) return ''
    const byUrl = new Map<string, ScanCheck[]>()
    for (const check of checks) byUrl.set(check.url, [...(byUrl.get(check.url) ?? []), check])
    return `<div class="scan-service"><h4>${scanServiceNames[service]}${service === 'google' || service === 'cloudflare' ? ' <span>контрольная проверка</span>' : ''}</h4>
      <div class="scan-grid scan-grid-head"><span>Адрес</span><span>HTTP/1.1</span><span>TLS 1.2</span><span>TLS 1.3</span></div>
      ${[...byUrl].map(([url, urlChecks]) => `<div class="scan-grid"><span class="scan-url" title="${escapeHtml(url)}">${escapeHtml(url.replace(/^https?:\/\//, ''))}</span>${(['http11', 'tls12', 'tls13'] as const).map((variant) => {
        const check = urlChecks.find((item) => item.variant === variant)
        if (!check) return '<span class="scan-cell is-skipped" title="Нет данных">—</span>'
        const detail = [scanVariantNames[variant], scanStatusNames[check.status], check.httpStatus ? `HTTP ${check.httpStatus}` : null, scanDuration(check.durationMs), check.error].filter(Boolean).join(' · ')
        return `<span class="scan-cell is-${check.status}" title="${escapeHtml(detail)}"><span class="scan-cell-state">${scanStatusNames[check.status]}</span>${check.httpStatus ? `<span>HTTP ${check.httpStatus}</span>` : ''}${check.durationMs !== null ? `<small>${scanDuration(check.durationMs)}</small>` : ''}${check.error ? `<small class="scan-cell-error">${escapeHtml(check.error)}</small>` : ''}</span>`
      }).join('')}</div>`).join('')}</div>`
  }).join('')
  return `<article class="scan-result-row" data-scan-key="${escapeHtml(key)}" data-scan-version="${version}"><button class="scan-row-toggle" type="button" data-scan-expand="${escapeHtml(key)}" aria-expanded="${expanded}"><span class="scan-row-name"><strong title="${escapeHtml(result.displayName)}">${escapeHtml(result.displayName)}</strong><small>${escapeHtml(heading ?? scanVerdictNames[result.verdict])}</small></span>${scanGroups.map((service) => scanServiceSummary(result, service)).join('')}<span class="scan-row-chevron" aria-hidden="true">${icon('chevron')}</span></button>${expanded ? `<div class="scan-row-detail">${rows || '<p class="scan-empty-result">Результаты проверок пока не получены.</p>'}</div>` : ''}</article>`
}

function scanResultEntries(): { result: ScanStrategyResult; heading?: string }[] {
  const scanned = [...(scanProgress?.results ?? [])]
    .filter((result) => !currentCheckResult || result.strategyId !== currentCheckResult.strategyId)
    .reverse()
    .map((result) => ({ result, heading: scanCurrentBusy ? 'Запущенная стратегия' : undefined }))
  return currentCheckResult ? [{ result: currentCheckResult, heading: 'Запущенная стратегия' }, ...scanned] : scanned
}

function scanResultsHead(): string {
  return `<div class="scan-results-head"><span>Стратегия</span>${scanGroups.map((service) => `<span>${scanServiceNames[service]}</span>`).join('')}<span></span></div>`
}

function renderScanDynamic(selectedCount: number, running: boolean, blocked: boolean, conflict: string | null): string {
  const canStart = selectedCount > 0 && !blocked && !conflict
  const progress = scanProgress
  const currentResult = progress?.results.find((result) => result.strategyId === progress.currentStrategyId)
  const currentName = currentResult?.displayName ?? altStrategies().find((item) => item.id === progress?.currentStrategyId)?.displayName ?? progress?.currentStrategyId
  const currentChecks = currentResult?.checks.length ?? 0
  const waitingSeconds = scanStartedAt ? Math.floor((Date.now() - scanStartedAt) / 1000) : 0
  const progressDetail = progress?.phase === 'testing' && currentName
    ? `${currentName} · ${currentChecks} / 33 запроса`
    : scanBusy && (!progress || progress.phase === 'preparing')
      ? `Ожидание UAC, остановки прежней стратегии и запуска ALT… ${waitingSeconds} с`
      : progress?.phase === 'restoring'
        ? 'Возвращаем исходное состояние…'
        : ''
  return `${scanRecoveryPending ? `<div class="scan-recovery" role="alert"><span>Предыдущая проверка прервалась. Восстановите исходную стратегию перед новым запуском.</span><button class="action-button" type="button" data-scan-action="recover" ${scanRecoverBusy ? 'disabled' : ''}>${icon('rollback')}<span>${scanRecoverBusy ? 'Восстанавливаем…' : 'Восстановить стратегию'}</span></button></div>` : ''}
    <div class="scan-actions"><button class="action-button primary-button" type="button" data-scan-action="start" ${canStart ? '' : 'disabled'}>${icon('power')}<span>Проверить ${selectedCount} ALT</span></button>${scanBusy ? `<button class="action-button danger-button" type="button" data-scan-action="cancel" ${scanCancelBusy ? 'disabled' : ''}>${icon('close')}<span>${scanCancelBusy || scanCancelRequested ? 'Останавливаем…' : 'Остановить тесты'}</span></button>` : ''}<button class="quiet-button" type="button" data-scan-action="current" ${running && !blocked && !conflict ? '' : 'disabled'}>${icon('refresh')}<span>${scanCurrentBusy ? 'Проверяем…' : 'Проверить текущую'}</span></button></div>
    ${conflict && !scanBusy ? `<p class="inline-warning">${escapeHtml(conflict)}</p>` : ''}
    ${scanError ? errorMarkup(scanError) : ''}
    <div class="scan-progress" role="status" aria-live="polite">${progress ? `<strong>${scanPhaseNames[progress.phase]}</strong><span>${progress.completedStrategies} / ${progress.totalStrategies} ALT</span>${progress.restoration !== 'none' ? `<span>${scanRestorationNames[progress.restoration]}</span>` : ''}` : scanBusy ? '<strong>Запускаем тесты</strong>' : '<span>Google и Cloudflare проверяются дополнительно и не влияют на итог ALT.</span>'}</div>
    ${progressDetail ? `<p class="scan-progress-detail">${escapeHtml(progressDetail)}</p>` : ''}
    ${scanCancelRequested && scanBusy ? '<p class="scan-progress-detail">Остановка запрошена. Дожидаемся завершения текущего запроса и восстановления стратегии.</p>' : ''}`
}

function renderTests(): string {
  const available = altStrategies()
  const selectedCount = scanAllStrategies ? available.length : available.filter((item) => scanSelectedIds.has(item.id)).length
  const running = manualSnapshot?.status.running === true
  const blocked = updateBusy || manualBusy || serviceConsoleBusy || scanCurrentBusy || scanBusy || scanRecoveryPending || scanRecoverBusy
  const conflict = manualConflict()
  return `<section class="tests-page">
    <div class="tests-heading"><h1>Тесты ALT</h1><p>Проверка HTTP-ответа и времени отклика. Воспроизведение видео и работа Discord требуют отдельной проверки.</p></div>
    <div class="tests-toolbar" aria-label="Параметры проверки">
      <fieldset class="scan-choice"><legend>Сервисы</legend><div class="scan-segments">${(['youtube', 'discord', 'both'] as const).map((scope) => `<label><input type="radio" name="scan-scope" value="${scope}" ${scanScope === scope ? 'checked' : ''} ${blocked ? 'disabled' : ''}><span>${scope === 'youtube' ? 'YouTube' : scope === 'discord' ? 'Discord' : 'Оба'}</span></label>`).join('')}</div></fieldset>
      <fieldset class="scan-choice"><legend>Стратегии</legend><div class="scan-segments"><label><input type="radio" name="scan-selection" value="all" ${scanAllStrategies ? 'checked' : ''} ${blocked ? 'disabled' : ''}><span>Все ALT</span></label><label><input type="radio" name="scan-selection" value="selected" ${!scanAllStrategies ? 'checked' : ''} ${blocked ? 'disabled' : ''}><span>Выбрать</span></label></div></fieldset>
      <label class="scan-fast"><input type="checkbox" id="scan-fast" ${scanFastMode ? 'checked' : ''} ${blocked ? 'disabled' : ''}><span>Быстрый режим<small>После первой ошибки — следующий ALT</small></span></label>
    </div>
    ${!scanAllStrategies ? `<div class="scan-strategies" aria-label="Выбранные ALT">${available.map((item) => `<label><input type="checkbox" data-scan-strategy="${escapeHtml(item.id)}" ${scanSelectedIds.has(item.id) ? 'checked' : ''} ${blocked ? 'disabled' : ''}><span>${escapeHtml(item.displayName)}</span></label>`).join('')}</div>` : ''}
    <div class="scan-dynamic">${renderScanDynamic(selectedCount, running, blocked, conflict)}</div>
    <div class="scan-results">${scanResultEntries().length ? scanResultsHead() : ''}${scanResultEntries().map(({ result, heading }) => scanResultRow(result, heading)).join('')}</div>
  </section>`
}

function patchTestsPage(): boolean {
  const page = content?.querySelector<HTMLElement>('.tests-page')
  const dynamic = page?.querySelector<HTMLElement>('.scan-dynamic')
  const list = page?.querySelector<HTMLElement>('.scan-results')
  if (!page || !dynamic || !list) return false

  const available = altStrategies()
  const selectedCount = scanAllStrategies ? available.length : available.filter((item) => scanSelectedIds.has(item.id)).length
  const running = manualSnapshot?.status.running === true
  const blocked = updateBusy || manualBusy || serviceConsoleBusy || scanCurrentBusy || scanBusy || scanRecoveryPending || scanRecoverBusy
  page.querySelectorAll<HTMLInputElement>('.tests-toolbar input, .scan-strategies input').forEach((input) => { input.disabled = blocked })
  const dynamicMarkup = renderScanDynamic(selectedCount, running, blocked, manualConflict())
  if (dynamic.dataset.markup !== dynamicMarkup) {
    dynamic.innerHTML = dynamicMarkup
    dynamic.dataset.markup = dynamicMarkup
  }

  const entries = scanResultEntries()
  const oldRows = [...list.querySelectorAll<HTMLElement>(':scope > .scan-result-row')]
  const oldPositions = new Map(oldRows.map((row) => [row, row.getBoundingClientRect().top]))
  const existing = new Map(oldRows.map((row) => [row.dataset.scanKey, row]))
  const wanted = new Set<string>()
  const added: HTMLElement[] = []
  let head = list.querySelector<HTMLElement>(':scope > .scan-results-head')
  if (entries.length && !head) {
    list.insertAdjacentHTML('afterbegin', scanResultsHead())
    head = list.querySelector<HTMLElement>(':scope > .scan-results-head')
  } else if (!entries.length && head) {
    head.remove()
    head = null
  }
  let cursor: ChildNode | null = head ? head.nextSibling : list.firstChild
  for (const { result, heading } of entries) {
    const key = `${heading ?? 'scan'}:${result.strategyId}`
    wanted.add(key)
    const version = `${result.checks.length}:${result.verdict}:${expandedScanResults.has(key)}`
    let row = existing.get(key)
    if (!row || row.dataset.scanVersion !== version) {
      const template = document.createElement('template')
      template.innerHTML = scanResultRow(result, heading)
      const fresh = template.content.firstElementChild as HTMLElement
      if (row) {
        const hadFocus = row.contains(document.activeElement)
        row.replaceChildren(...fresh.childNodes)
        row.dataset.scanVersion = version
        if (hadFocus) row.querySelector<HTMLButtonElement>('.scan-row-toggle')?.focus({ preventScroll: true })
      } else {
        row = fresh
        added.push(row)
      }
    }
    if (row !== cursor) list.insertBefore(row, cursor)
    cursor = row.nextSibling
  }
  for (const row of oldRows) {
    if (!wanted.has(row.dataset.scanKey ?? '')) row.remove()
  }
  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    for (const [row, previousTop] of oldPositions) {
      if (!row.isConnected) continue
      const offset = previousTop - row.getBoundingClientRect().top
      if (Math.abs(offset) > 1) row.animate([{ transform: `translateY(${offset}px)` }, { transform: 'translateY(0)' }], { duration: 260, easing: 'ease-out' })
    }
    for (const row of added) {
      row.animate([{ opacity: 0, transform: 'translateY(-12px)' }, { opacity: 1, transform: 'translateY(0)' }], { duration: 280, easing: 'ease-out' })
    }
  }
  return true
}

function renderCurrentPage(forceTests = false): void {
  if (currentPage === 'home' && document.activeElement === content?.querySelector('#strategy-select') && !manualBusy && !updateBusy) {
    deferredHomeRender = true
    return
  }
  if (currentPage === 'tests' && !forceTests && patchTestsPage()) return
  deferredHomeRender = false
  content!.innerHTML = currentPage === 'home' ? renderHome() : currentPage === 'tests' ? renderTests() : renderAppearance()
  applyAppearancePreview()
}

async function refreshDiagnostics(): Promise<void> {
  try { diagnostics = await getDiagnostics(); diagnosticsError = null }
  catch (error) { diagnostics = null; diagnosticsError = toAppError(error) }
  if (currentPage === 'home') renderCurrentPage()
}

async function refreshConfig(): Promise<void> {
  if (configLoading) return
  configLoading = true
  configError = null
  renderCurrentPage()
  try {
    const refreshedConfig = await getConfig()
    const preserveAppearanceDraft = !!appearanceDraft && appearanceIsDirty()
    config = refreshedConfig
    if (!selectedStrategyId) selectedStrategyId = config.selectedStrategy
    if (!preserveAppearanceDraft) {
      appearanceDraft = cloneAppearance(config.appearance ?? defaultAppearance)
      appearanceError = null
      void loadAppearanceAssets(appearanceDraft)
    }
  } catch (error) {
    config = null
    configError = toAppError(error)
  } finally {
    configLoading = false
    renderCurrentPage()
  }
}

async function refreshStrategies(): Promise<void> {
  strategiesError = null
  renderCurrentPage()
  try {
    strategies = await getStrategies()
    if (!selectedStrategyId) selectedStrategyId = config?.selectedStrategy ?? null
  } catch (error) {
    strategies = null
    strategiesError = toAppError(error)
  } finally {
    renderCurrentPage(currentPage === 'tests')
  }
}

async function refreshManualStatus(): Promise<void> {
  if (manualPolling) return
  manualPolling = true
  manualStatusError = null
  try {
    manualSnapshot = await getManualStatus()
    if (manualSnapshot.status.strategyId) selectedStrategyId = manualSnapshot.status.strategyId
    if (manualSnapshot.status.running) {
      if (manualPollTimer !== null) window.clearTimeout(manualPollTimer)
      manualPollTimer = window.setTimeout(() => { void refreshManualStatus() }, 3000)
    } else if (manualPollTimer !== null) {
      window.clearTimeout(manualPollTimer)
      manualPollTimer = null
    }
  } catch (error) {
    manualStatusError = toAppError(error)
    if (manualSnapshot?.status.running) {
      if (manualPollTimer !== null) window.clearTimeout(manualPollTimer)
      manualPollTimer = window.setTimeout(() => { void refreshManualStatus() }, 6000)
    }
  } finally {
    manualPolling = false
    if (currentPage === 'home') renderCurrentPage()
  }
}

async function runManualAction(action: 'start' | 'stop'): Promise<void> {
  if (manualBusy || updateBusy || scanBusy || scanCurrentBusy) return
  const selected = strategyById(selectedStrategyId)
  if (action === 'start' && (!selected?.supported || manualConflict())) return
  manualBusy = true
  manualActionError = null
  renderCurrentPage()
  try {
    manualSnapshot = action === 'start' ? await startManual(selected!.id) : await stopManual()
    manualStatusError = null
    await refreshDiagnostics()
    if (manualSnapshot.status.running) {
      if (manualPollTimer !== null) window.clearTimeout(manualPollTimer)
      manualPollTimer = window.setTimeout(() => { void refreshManualStatus() }, 3000)
    }
  } catch (error) {
    manualActionError = toAppError(error)
    await refreshManualStatus()
    await refreshDiagnostics()
  } finally { manualBusy = false; renderCurrentPage() }
}

async function runEngineUpdate(rollback = false): Promise<void> {
  if (updateBusy || manualBusy || scanBusy || scanCurrentBusy) return
  const operationId = crypto.randomUUID()
  updateBusy = true
  updateError = null
  updateFinished = null
  updateCleanupWarning = null
  updateProgress = null
  renderCurrentPage()
  let unlisten: (() => void) | null = null
  try {
    unlisten = await listen<EngineUpdateProgress>('engine-update-progress', (event) => {
      if (event.payload.operationId !== operationId || (updateProgress && event.payload.sequence <= updateProgress.sequence)) return
      updateProgress = event.payload
      renderCurrentPage()
    })
    const result = rollback ? await rollbackEngine(operationId) : await updateEngine(operationId)
    updateFinished = rollback ? 'Откат выполнен' : 'Обновлено'
    updateCleanupWarning = result.cleanupWarning
    await Promise.all([refreshDiagnostics(), refreshStrategies(), refreshManualStatus()])
  } catch (error) {
    updateError = toAppError(error)
    await Promise.all([refreshDiagnostics(), refreshStrategies(), refreshManualStatus()])
  } finally {
    rollbackAvailable = await getRollbackAvailable().catch(() => false)
    unlisten?.()
    updateBusy = false
    renderCurrentPage()
  }
}

async function runServiceConsole(): Promise<void> {
  if (serviceConsoleBusy || updateBusy || manualBusy || scanBusy || scanCurrentBusy) return
  serviceConsoleBusy = true
  serviceConsoleError = null
  renderCurrentPage()
  try { await openServiceConsole() }
  catch (error) { serviceConsoleError = toAppError(error) }
  finally { serviceConsoleBusy = false; renderCurrentPage() }
}

function selectPage(id: PageId): void {
  currentPage = id
  app!.querySelector('.main-panel')?.classList.toggle('is-appearance', id === 'appearance')
  app!.querySelector('.main-panel')?.classList.toggle('is-tests', id === 'tests')
  document.querySelectorAll<HTMLButtonElement>('.nav-item').forEach((button) => {
    const selected = button.dataset.page === id
    button.classList.toggle('active', selected)
    button.setAttribute('aria-current', selected ? 'page' : 'false')
  })
  renderCurrentPage()
  content!.scrollTo(0, 0)
  if (id === 'appearance' && (!config || configError) && !configLoading) void refreshConfig()
}

const scanEventsReady = listen<ScanProgress>('strategy-scan-progress', (event) => {
  const incoming = event.payload
  if (scanOperationId && incoming.operationId !== scanOperationId) return
  if (scanProgress?.operationId === incoming.operationId && incoming.sequence <= scanProgress.sequence) return
  scanBackendSeen = true
  scanOperationId = incoming.operationId
  scanProgress = incoming
  if (incoming.error) scanError = incoming.error
  scanBusy = !['completed', 'cancelled', 'failed'].includes(incoming.phase)
  if (!scanBusy) {
    scanCancelBusy = false
    scanCancelRequested = false
  }
  if (currentPage === 'tests' || currentPage === 'home') renderCurrentPage()
})

async function restoreScanState(commandSettled = false): Promise<void> {
  try {
    const state = await getStrategyScanState()
    if (state.active) scanBackendSeen = true
    const progressMatches = !scanBusy || !scanOperationId || state.progress?.operationId === scanOperationId
    if (state.progress && progressMatches && (!scanProgress || state.progress.operationId !== scanProgress.operationId || state.progress.sequence >= scanProgress.sequence)) {
      scanProgress = state.progress
      scanOperationId = state.progress.operationId
      if (state.progress.error) scanError = state.progress.error
    }
    // A just-issued IPC request may not have reached the Rust command yet.
    // Only an observed backend session may be reconciled to inactive here.
    if (state.active || scanBackendSeen || commandSettled || !scanBusy) scanBusy = state.active
    if (!scanBusy) {
      scanCancelBusy = false
      scanCancelRequested = false
      scanCurrentBusy = false
      scanBackendSeen = false
    }
    scanRecoveryPending = state.recoveryPending
    if (currentPage === 'tests' || currentPage === 'home') renderCurrentPage()
  } catch (error) {
    scanError = toAppError(error)
    if (currentPage === 'tests') renderCurrentPage()
  }
}

async function runStrategyScan(): Promise<void> {
  if (scanBusy || scanCurrentBusy || scanRecoveryPending || scanRecoverBusy || updateBusy || manualBusy || serviceConsoleBusy || manualConflict()) return
  const strategyIds = altStrategies().filter((item) => scanAllStrategies || scanSelectedIds.has(item.id)).map((item) => item.id)
  if (!strategyIds.length) return
  const operationId = crypto.randomUUID()
  scanOperationId = operationId
  scanBusy = true
  scanStartedAt = Date.now()
  scanBackendSeen = false
  scanCancelBusy = false
  scanCancelRequested = false
  scanError = null
  scanProgress = null
  currentCheckResult = null
  expandedScanResults.clear()
  renderCurrentPage()
  try {
    await scanEventsReady
    scanProgress = await startStrategyScan(operationId, strategyIds, scanScope, scanFastMode)
    if (scanProgress.error) scanError = scanProgress.error
  } catch (error) {
    scanError = toAppError(error)
  } finally {
    await restoreScanState(true)
    scanCancelBusy = false
    await Promise.all([refreshManualStatus(), refreshDiagnostics()])
    renderCurrentPage()
  }
}

async function runScanCancel(): Promise<void> {
  if (!scanBusy || !scanOperationId || scanCancelBusy) return
  scanCancelBusy = true
  renderCurrentPage()
  try {
    await cancelStrategyScan(scanOperationId)
    scanCancelRequested = true
  } catch (error) {
    scanError = toAppError(error)
    await restoreScanState()
  } finally {
    scanCancelBusy = false
    renderCurrentPage()
  }
}

async function runCurrentStrategyCheck(): Promise<void> {
  if (!manualSnapshot?.status.running || scanBusy || scanCurrentBusy || scanRecoveryPending || scanRecoverBusy || updateBusy || manualBusy || manualConflict()) return
  const operationId = crypto.randomUUID()
  scanOperationId = operationId
  scanBusy = true
  scanStartedAt = Date.now()
  scanBackendSeen = false
  scanCancelBusy = false
  scanCancelRequested = false
  scanCurrentBusy = true
  scanError = null
  currentCheckResult = null
  scanProgress = null
  expandedScanResults.clear()
  renderCurrentPage()
  try {
    await scanEventsReady
    currentCheckResult = await checkCurrentStrategy(operationId, scanScope)
  }
  catch (error) { scanError = toAppError(error) }
  finally {
    scanCurrentBusy = false
    scanCancelBusy = false
    await restoreScanState(true)
    renderCurrentPage()
  }
}

async function runScanRecovery(): Promise<void> {
  if (!scanRecoveryPending || scanRecoverBusy || scanBusy) return
  scanRecoverBusy = true
  scanError = null
  renderCurrentPage()
  try { await recoverStrategyScan() }
  catch (error) { scanError = toAppError(error) }
  finally {
    scanRecoverBusy = false
    await Promise.all([restoreScanState(), refreshManualStatus(), refreshDiagnostics()])
    renderCurrentPage()
  }
}

async function importAppearanceFile(file: File): Promise<void> {
  if (!appearanceDraft || appearanceBusy) return
  const maxBytes = 8 * 1024 * 1024
  const extension = file.name.split('.').at(-1)?.toLowerCase() ?? ''
  const allowedMime: Record<string, string[]> = {
    png: ['image/png'],
    jpg: ['image/jpeg', 'image/jpg'],
    jpeg: ['image/jpeg', 'image/jpg'],
    webp: ['image/webp']
  }
  if (!Object.hasOwn(allowedMime, extension)) {
    appearanceError = { message: 'Этот формат изображения не поддерживается.', action: 'Выберите PNG, JPEG или WebP.' }
    renderCurrentPage()
    return
  }
  if (file.type && !allowedMime[extension].includes(file.type.toLowerCase())) {
    appearanceError = { message: 'Расширение файла не совпадает с его типом.', action: 'Выберите корректный PNG, JPEG или WebP файл.' }
    renderCurrentPage()
    return
  }
  if (file.size === 0 || file.size > maxBytes) {
    appearanceError = { message: 'Размер файла должен быть больше нуля и не превышать 8 МиБ.', action: 'Выберите изображение меньшего размера.' }
    renderCurrentPage()
    return
  }
  appearanceBusy = true
  appearanceError = null
  appearanceMessage = null
  renderCurrentPage()
  try {
    const bytes = new Uint8Array(await file.arrayBuffer())
    const imported = await importAppearanceAsset(bytes, extension)
    appearanceDraft = { ...appearanceDraft, backgroundAsset: imported.assetId }
    appearanceAssetError = null
    await loadAppearanceAssets(appearanceDraft)
    appearanceMessage = 'Файл скопирован локально. Нажмите «Сохранить оформление», чтобы закрепить изменения.'
  } catch (error) {
    appearanceError = toAppError(error)
  } finally {
    appearanceBusy = false
    renderCurrentPage()
  }
}

async function runAppearanceAction(action: string): Promise<void> {
  if (!appearanceDraft || !config || appearanceBusy) return
  appearanceError = null
  appearanceMessage = null
  if (action === 'reset-background') {
    appearanceDraft = {
      ...appearanceDraft,
      backgroundAsset: null,
      backgroundOpacity: defaultAppearance.backgroundOpacity,
      backgroundBlur: defaultAppearance.backgroundBlur,
      backgroundPositionX: defaultAppearance.backgroundPositionX,
      backgroundPositionY: defaultAppearance.backgroundPositionY,
      backgroundScale: defaultAppearance.backgroundScale,
      backgroundFit: defaultAppearance.backgroundFit,
      darkOverlay: defaultAppearance.darkOverlay
    }
    appearanceAssetError = null
    backgroundPreviewUrl = null
    applyAppearancePreview(null)
    void loadAppearanceAssets(appearanceDraft)
    renderCurrentPage()
    return
  }
  if (action === 'cancel') {
    appearanceDraft = cloneAppearance(config.appearance)
    appearanceAssetError = null
    appearanceError = null
    appearanceMessage = 'Несохранённые изменения отменены.'
    await loadAppearanceAssets(appearanceDraft)
    renderCurrentPage()
    return
  }
  if (action !== 'save') return
  appearanceBusy = true
  renderCurrentPage()
  try {
    config = await saveAppearance(appearanceDraft)
    appearanceDraft = cloneAppearance(config.appearance)
    appearanceMessage = 'Настройки оформления сохранены на этом компьютере.'
    appearanceAssetError = null
    await loadAppearanceAssets(appearanceDraft)
  } catch (error) {
    appearanceError = toAppError(error)
  } finally {
    appearanceBusy = false
    renderCurrentPage()
  }
}

function updateAppearanceRange(key: keyof AppearanceSettings, value: number): void {
  if (!appearanceDraft) return
  appearanceDraft = { ...appearanceDraft, [key]: value }
  applyAppearancePreview()
  const valueLabel = content?.querySelector<HTMLElement>(`[data-appearance-value="${key}"]`)
  if (valueLabel) valueLabel.textContent = `${value}${key === 'backgroundBlur' ? ' px' : key.toLowerCase().includes('opacity') || key === 'darkOverlay' || key === 'backgroundScale' || key === 'mascotScale' || key.includes('Position') ? '%' : ''}`
  const dirtyLabel = content?.querySelector<HTMLElement>('.appearance-dirty')
  if (dirtyLabel) dirtyLabel.textContent = appearanceIsDirty() ? 'Есть несохранённые изменения.' : appearanceMessage ?? 'Настройки сохранены.'
  syncAppearanceActionButtons()
}

document.querySelectorAll<HTMLButtonElement>('.nav-item').forEach((button) => button.addEventListener('click', () => selectPage(button.dataset.page as PageId)))
content.addEventListener('focusout', (event) => {
  if ((event.target as HTMLElement).id !== 'strategy-select' || !deferredHomeRender) return
  window.requestAnimationFrame(() => {
    if (currentPage === 'home' && document.activeElement?.id !== 'strategy-select') renderCurrentPage()
  })
})
content.addEventListener('click', (event) => {
  const target = event.target
  if (!(target instanceof Element)) return
  const expand = target.closest<HTMLButtonElement>('[data-scan-expand]')?.dataset.scanExpand
  if (expand) {
    if (expandedScanResults.has(expand)) expandedScanResults.delete(expand)
    else expandedScanResults.add(expand)
    renderCurrentPage()
    const toggled = [...content!.querySelectorAll<HTMLButtonElement>('[data-scan-expand]')].find((button) => button.dataset.scanExpand === expand)
    toggled?.focus({ preventScroll: true })
    return
  }
  const manual = target.closest<HTMLButtonElement>('[data-manual-action]')?.dataset.manualAction
  if (manual === 'start' || manual === 'stop') void runManualAction(manual)
  if (target.closest('#update-engine')) void runEngineUpdate()
  if (target.closest('#rollback-engine')) void runEngineUpdate(true)
  if (target.closest('#open-service-console')) void runServiceConsole()
  const scanAction = target.closest<HTMLButtonElement>('[data-scan-action]')?.dataset.scanAction
  if (scanAction === 'start') void runStrategyScan()
  if (scanAction === 'cancel') void runScanCancel()
  if (scanAction === 'current') void runCurrentStrategyCheck()
  if (scanAction === 'recover') void runScanRecovery()
  const appearanceAction = target.closest<HTMLButtonElement>('[data-appearance-action]')?.dataset.appearanceAction
  if (appearanceAction) void runAppearanceAction(appearanceAction)
  const appearanceChoose = target.closest<HTMLButtonElement>('[data-appearance-choose]')?.dataset.appearanceChoose
  if (appearanceChoose === 'background') content!.querySelector<HTMLInputElement>('[data-appearance-file="background"]')?.click()
})
content.addEventListener('change', (event) => {
  const target = event.target
  if (target instanceof HTMLInputElement && target.name === 'scan-scope') {
    scanScope = target.value === 'youtube' || target.value === 'discord' ? target.value : 'both'
    currentCheckResult = null
    renderCurrentPage(true)
    return
  }
  if (target instanceof HTMLInputElement && target.name === 'scan-selection') {
    scanAllStrategies = target.value !== 'selected'
    if (!scanAllStrategies && scanSelectedIds.size === 0) {
      scanSelectedIds = new Set(altStrategies().map((item) => item.id))
    }
    renderCurrentPage(true)
    return
  }
  if (target instanceof HTMLInputElement && target.id === 'scan-fast') {
    scanFastMode = target.checked
    return
  }
  if (target instanceof HTMLInputElement && target.dataset.scanStrategy) {
    if (target.checked) scanSelectedIds.add(target.dataset.scanStrategy)
    else scanSelectedIds.delete(target.dataset.scanStrategy)
    renderCurrentPage(true)
    return
  }
  if (target instanceof HTMLInputElement && target.dataset.appearanceFile) {
    const file = target.files?.[0]
    if (file) void importAppearanceFile(file)
    target.value = ''
    return
  }
  if (target instanceof HTMLSelectElement && target.dataset.appearanceFit) {
    if (appearanceDraft) {
      appearanceDraft = { ...appearanceDraft, backgroundFit: target.value === 'contain' ? 'contain' : 'cover' }
      appearanceMessage = null
      applyAppearancePreview()
      const dirtyLabel = content!.querySelector<HTMLElement>('.appearance-dirty')
      if (dirtyLabel) dirtyLabel.textContent = appearanceIsDirty() ? 'Есть несохранённые изменения.' : 'Настройки сохранены.'
      syncAppearanceActionButtons()
    }
    return
  }
  if (!(target instanceof HTMLSelectElement) || target.id !== 'strategy-select') return
  const strategy = strategyById(target.value)
  if (!strategy?.supported) return
  void (async () => {
    manualActionError = null
    manualBusy = true
    renderCurrentPage()
    try {
      await selectStrategy(strategy.id)
      selectedStrategyId = strategy.id
      if (config) config = { ...config, selectedStrategy: strategy.id }
    } catch (error) { manualActionError = toAppError(error) }
    finally { manualBusy = false; renderCurrentPage() }
  })()
})
content.addEventListener('input', (event) => {
  const target = event.target
  if (target instanceof HTMLInputElement && target.dataset.appearanceRange) {
    const value = Number(target.value)
    if (Number.isFinite(value)) updateAppearanceRange(target.dataset.appearanceRange as keyof AppearanceSettings, value)
  }
})
window.addEventListener('beforeunload', () => {
  for (const url of appearanceAssetUrls.values()) URL.revokeObjectURL(url)
  appearanceAssetUrls.clear()
})
selectPage('home')
void Promise.all([refreshConfig(), refreshStrategies(), refreshManualStatus(), refreshDiagnostics()])
void restoreScanState()
window.setInterval(() => {
  if (!scanBusy || scanStatePolling) return
  scanStatePolling = true
  void restoreScanState().finally(() => { scanStatePolling = false })
}, 2000)
void getRollbackAvailable().then((available) => { rollbackAvailable = available; renderCurrentPage() }).catch(() => {})
