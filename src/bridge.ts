import { invoke } from '@tauri-apps/api/core'

export type EngineUpdateStage = 'download' | 'validate' | 'stopService' | 'stopManual' | 'stopWinDivert' | 'replace' | 'restore' | 'complete'

export interface EngineUpdateProgress {
  operationId: string
  sequence: number
  stage: EngineUpdateStage
  state: 'started' | 'completed' | 'failed'
  message: string
  detail: string | null
}

export interface EngineUpdateResult {
  release: string
  restoredMode: 'manual' | 'stopped'
  cleanupWarning: AppError | null
}

export type ComponentState = 'running' | 'stopped' | 'pending' | 'error' | 'unknown' | 'missing'

export interface DiagnosticsSnapshot {
  checkedAt: string
  paths: {
    configDir: string
    dataDir: string
    engineDir: string
    logDir: string
  }
  engine: {
    installed: boolean
    ready: boolean
    issue?: string | null
  }
  service: {
    installed: boolean
    state: ComponentState
    processId?: number | null
    strategy?: string | null
    executablePath?: string | null
    managed: boolean
    error?: string | null
  }
  winDivert: {
    installed: boolean
    managed: boolean
    state: ComponentState
    name?: string | null
    driverFilePresent: boolean
    error?: string | null
  }
  processes: Array<{
    pid: number
    executablePath?: string | null
    managed: boolean
    error?: string | null
  }>
  warnings: string[]
}

export interface AppConfig {
  schemaVersion: 2
  selectedStrategy: string | null
  logRetentionDays: number
  appearance: AppearanceSettings
}

export type BackgroundFit = 'cover' | 'contain'

export interface AppearanceSettings {
  backgroundAsset: string | null
  mascotAsset: string | null
  backgroundOpacity: number
  backgroundBlur: number
  backgroundPositionX: number
  backgroundPositionY: number
  backgroundScale: number
  backgroundFit: BackgroundFit
  mascotScale: number
  mascotPositionX: number
  mascotPositionY: number
  mascotOpacity: number
  darkOverlay: number
}

export interface AppearanceAsset {
  assetId: string
  mime: string
}

export interface StrategyInfo {
  id: string
  displayName: string
  sourceFile: string
  release: string
  supported: boolean
  unsupportedReason?: string | null
}

export type ScanScope = 'youtube' | 'discord' | 'both'
export type ScanPhase = 'preparing' | 'testing' | 'restoring' | 'completed' | 'cancelled' | 'failed'
export type ScanCheckStatus = 'passed' | 'failed' | 'unsupported' | 'skipped'

export interface ScanCheck {
  endpointKey?: string
  category: 'youtube' | 'discord' | 'google' | 'cloudflare'
  url: string
  variant: 'http11' | 'tls12' | 'tls13'
  status: ScanCheckStatus
  httpStatus: number | null
  durationMs: number | null
  error: string | null
}

export interface ScanStrategyResult {
  strategyId: string
  displayName: string
  verdict: 'passed' | 'failed' | 'incomplete' | 'unsupported'
  checks: ScanCheck[]
}

export interface ScanProgress {
  operationId: string
  sequence: number
  phase: ScanPhase
  currentStrategyId: string | null
  completedStrategies: number
  totalStrategies: number
  results: ScanStrategyResult[]
  restoration: 'none' | 'pending' | 'restored' | 'failed'
  error: AppError | null
}

export interface ScanState {
  active: boolean
  progress: ScanProgress | null
  recoveryPending: boolean
}

export type ScanSummary = ScanProgress

export type ManualProcessState = 'running' | 'stopped' | 'error'

export interface ProcessStatus {
  running: boolean
  state: ManualProcessState
  strategyId?: string | null
  strategyName?: string | null
  pid?: number | null
  executablePath?: string | null
  createdAtMs?: number | null
  exitCode?: number | null
  error?: AppError | null
}

export interface ManualSnapshot {
  status: ProcessStatus
}

export interface AppError {
  code?: string
  message: string
  action?: string | null
  detail?: string | null
}

export function toAppError(error: unknown): AppError {
  if (typeof error === 'object' && error !== null && 'message' in error && typeof error.message === 'string') {
    const value = error as Record<string, unknown>
    return {
      code: typeof value.code === 'string' ? value.code : undefined,
      message: error.message,
      action: typeof value.action === 'string' ? value.action : undefined,
      detail: typeof value.detail === 'string' ? value.detail : undefined
    }
  }
  return { message: 'Не удалось получить данные приложения.', action: 'Повторите попытку.' }
}

export function getDiagnostics(): Promise<DiagnosticsSnapshot> {
  return invoke<DiagnosticsSnapshot>('get_diagnostics')
}

export function getConfig(): Promise<AppConfig> {
  return invoke<AppConfig>('get_config')
}

export function saveAppearance(settings: AppearanceSettings): Promise<AppConfig> {
  return invoke<AppConfig>('save_appearance', { settings })
}

export function importAppearanceAsset(bytes: Uint8Array, extension: string): Promise<AppearanceAsset> {
  return invoke<AppearanceAsset>('import_appearance_asset', bytes, {
    headers: { 'x-image-extension': extension }
  })
}

export function readAppearanceAsset(assetId: string): Promise<ArrayBuffer> {
  return invoke<ArrayBuffer>('read_appearance_asset', { assetId })
}

export function getStrategies(): Promise<StrategyInfo[]> {
  return invoke<StrategyInfo[]>('get_strategies')
}

export function selectStrategy(strategyId: string): Promise<void> {
  return invoke<void>('select_strategy', { strategyId })
}

export function startManual(strategyId: string): Promise<ManualSnapshot> {
  return invoke<ManualSnapshot>('start_manual', { strategyId })
}

export function stopManual(): Promise<ManualSnapshot> {
  return invoke<ManualSnapshot>('stop_manual')
}

export function getManualStatus(): Promise<ManualSnapshot> {
  return invoke<ManualSnapshot>('get_manual_status')
}

export function updateEngine(operationId: string): Promise<EngineUpdateResult> {
  return invoke<EngineUpdateResult>('update_engine', { operationId })
}

export function rollbackEngine(operationId: string): Promise<EngineUpdateResult> {
  return invoke<EngineUpdateResult>('rollback_engine', { operationId })
}

export function getRollbackAvailable(): Promise<boolean> {
  return invoke<boolean>('get_rollback_available')
}

export function openServiceConsole(): Promise<void> {
  return invoke<void>('open_service_console')
}

export function startStrategyScan(operationId: string, strategyIds: string[], scope: ScanScope, fastMode: boolean): Promise<ScanSummary> {
  return invoke<ScanSummary>('start_strategy_scan', { operationId, strategyIds, scope, fastMode })
}

export function cancelStrategyScan(operationId: string): Promise<void> {
  return invoke<void>('cancel_strategy_scan', { operationId })
}

export function checkCurrentStrategy(operationId: string, scope: ScanScope): Promise<ScanStrategyResult> {
  return invoke<ScanStrategyResult>('check_current_strategy', { operationId, scope })
}

export function getStrategyScanState(): Promise<ScanState> {
  return invoke<ScanState>('get_strategy_scan_state')
}

export function recoverStrategyScan(): Promise<void> {
  return invoke<void>('recover_strategy_scan')
}

