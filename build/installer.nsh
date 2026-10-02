!macro customInstall
  WriteRegStr HKCU "Software\Google\Chrome\NativeMessagingHosts\com.fuin.nativehost" "" "$APPDATA\Fuin\com.fuin.nativehost-chrome.json"
  WriteRegStr HKCU "Software\Microsoft\Edge\NativeMessagingHosts\com.fuin.nativehost" "" "$APPDATA\Fuin\com.fuin.nativehost-chrome.json"
  WriteRegStr HKCU "Software\Mozilla\NativeMessagingHosts\com.fuin.nativehost" "" "$APPDATA\Fuin\com.fuin.nativehost-firefox.json"
!macroend

!macro customUnInstall
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\com.fuin.nativehost"
  DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\com.fuin.nativehost"
  DeleteRegKey HKCU "Software\Mozilla\NativeMessagingHosts\com.fuin.nativehost"
!macroend
