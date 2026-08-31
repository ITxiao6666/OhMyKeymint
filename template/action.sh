#!/system/bin/sh

MOD_ID=oh_my_keymint
STANDALONE_COMPONENT=io.github.a13e300.ksuwebui/.WebUIActivity
WEBUI_X_COMPONENT=com.dergoogler.mmrl.wx/.ui.activity.webui.WebUIActivity

if pm path io.github.a13e300.ksuwebui >/dev/null 2>&1; then
  echo "- Opening Oh My Keymint WebUI"
  exec am start -n "$STANDALONE_COMPONENT" -e id "$MOD_ID"
fi

if pm path com.dergoogler.mmrl.wx >/dev/null 2>&1; then
  echo "- Opening Oh My Keymint WebUI"
  exec am start -n "$WEBUI_X_COMPONENT" -e MOD_ID "$MOD_ID"
fi

echo "! No compatible WebUI host is installed"
echo "! Install KSUWebUIStandalone or WebUI X, then run this action again"
am start -a android.intent.action.VIEW \
  -d "https://github.com/KOWX712/KsuWebUIStandalone/releases" >/dev/null 2>&1 || true
exit 1
