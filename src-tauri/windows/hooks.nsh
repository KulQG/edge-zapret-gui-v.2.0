; Fixed protected installation; no shell commands or automatic process termination.
!define MUI_DIRECTORYPAGE_TEXT_TOP "Приложение устанавливается для всех пользователей в защищённую папку Program Files. Это необходимо для безопасных операций с правами администратора."

Function .onVerifyInstDir
  StrCmp $INSTDIR "$PROGRAMFILES64\ZAPRET GUI" valid
  Abort
valid:
FunctionEnd

!macro ZAPRET_REQUIRE_FIXED_PATH
  ${If} $INSTDIR != "$PROGRAMFILES64\ZAPRET GUI"
    MessageBox MB_OK|MB_ICONSTOP "Установка разрешена только в $PROGRAMFILES64\ZAPRET GUI. Повторите установку с папкой по умолчанию."
    Abort
  ${EndIf}
!macroend

!macro ZAPRET_REQUIRE_CLOSED
  !insertmacro RestartManager_StartSession $R0
  ${If} $R0 == ""
    MessageBox MB_OK|MB_ICONSTOP "Не удалось проверить работающие приложения. Закройте ZAPRET GUI и повторите действие."
    Abort
  ${EndIf}
  !insertmacro RestartManager_RegisterFile $R0 "$INSTDIR\${MAINBINARYNAME}.exe"
  ${If} $0 != 0
    !insertmacro RestartManager_EndSession $R0
    MessageBox MB_OK|MB_ICONSTOP "Не удалось проверить файл приложения. Повторите действие после перезапуска Windows."
    Abort
  ${EndIf}
  System::Call 'RSTRTMGR::RmGetList(i R0, *i .r1, *i 0, p 0, *i .r3)i.r0'
  !insertmacro RestartManager_EndSession $R0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Файл ZAPRET GUI используется или недоступен для проверки. Завершите обновление, затем закройте приложение и повторите действие."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro ZAPRET_REQUIRE_FIXED_PATH
  !insertmacro ZAPRET_REQUIRE_CLOSED
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ClearErrors
  ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --prepare-engine-storage' $0
  ${If} ${Errors}
  ${OrIf} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Не удалось подготовить защищённую папку движка. Установка не завершена. Проверьте сообщение приложения и повторите установку."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro ZAPRET_REQUIRE_FIXED_PATH
  !insertmacro ZAPRET_REQUIRE_CLOSED
  StrCpy $0 0
  System::Call 'advapi32::OpenSCManagerW(p 0, p 0, i 1)p.r0'
  ${If} $0 == 0
    MessageBox MB_OK|MB_ICONSTOP "Не удалось проверить службу zapret. Удаление отменено; проверьте права администратора."
    Abort
  ${EndIf}
  StrCpy $R0 $0
  StrCpy $1 0
  ; Capture the API error inside this System::Call. A second System::Call may
  ; change the thread's last error before GetLastError can read OpenServiceW's.
  System::Call 'advapi32::OpenServiceW(p R0, w "zapret", i 4)p.r1 ?e'
  Pop $2
  System::Call 'advapi32::CloseServiceHandle(p R0)'
  ${If} $1 != 0
    System::Call 'advapi32::CloseServiceHandle(p r1)'
    MessageBox MB_OK|MB_ICONSTOP "Служба zapret установлена. Откройте в ZAPRET GUI официальный service.bat и выберите Remove Services. Затем закройте приложение и повторите удаление. Движок и личные данные будут сохранены."
    Abort
  ${ElseIf} $2 != 1060
    MessageBox MB_OK|MB_ICONSTOP "Состояние службы zapret неизвестно (код Windows $2). Удаление отменено; проверьте службу средствами Windows."
    Abort
  ${EndIf}
!macroend
