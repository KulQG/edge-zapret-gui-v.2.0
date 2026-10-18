use serde::Serialize;
use std::fmt;

/// Stable error codes are suitable for diagnostics; UI text is always Russian.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    pub code: String,
    pub message: String,
    pub action: String,
    pub detail: Option<String>,
}

impl AppError {
    pub fn new(code: &'static str, message: &'static str, action: &'static str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
            action: action.to_owned(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: String) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn data_directory() -> Self {
        Self::new(
            "data_directory_unavailable",
            "Не удалось определить папку данных приложения.",
            "Проверьте доступ к профилю Windows и повторите попытку.",
        )
    }

    pub fn config_read() -> Self {
        Self::new(
            "config_read_failed",
            "Не удалось прочитать настройки приложения.",
            "Проверьте доступ к папке настроек и повторите попытку.",
        )
    }

    pub fn config_invalid() -> Self {
        Self::new(
            "config_invalid",
            "Файл настроек повреждён или содержит недопустимые значения.",
            "Проверьте файл настроек. Приложение не будет автоматически перезаписывать его.",
        )
    }

    pub fn config_unsupported() -> Self {
        Self::new(
            "config_version_unsupported",
            "Версия файла настроек не поддерживается этой версией приложения.",
            "Обновите приложение или восстановите совместимый файл настроек.",
        )
    }

    pub fn config_write() -> Self {
        Self::new(
            "config_write_failed",
            "Не удалось сохранить настройки приложения.",
            "Проверьте свободное место и права доступа к папке настроек, затем повторите попытку.",
        )
    }

    pub fn log_invalid() -> Self {
        Self::new(
            "log_event_invalid",
            "Не удалось записать событие диагностики: неверный формат данных.",
            "Повторите действие. Если ошибка повторяется, сообщите код события разработчику.",
        )
    }

    pub fn log_io() -> Self {
        Self::new(
            "log_io_failed",
            "Не удалось записать журнал приложения.",
            "Проверьте свободное место и доступ к папке журналов.",
        )
    }

    pub fn diagnostics() -> Self {
        Self::new(
            "diagnostics_failed",
            "Не удалось собрать сведения о состоянии системы.",
            "Повторите проверку. Если ошибка повторится, откройте журнал приложения.",
        )
    }

    pub fn task_join() -> Self {
        Self::new(
            "background_task_failed",
            "Фоновая операция была прервана.",
            "Повторите действие. Если ошибка повторится, перезапустите приложение.",
        )
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for AppError {}
