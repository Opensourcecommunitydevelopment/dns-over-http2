Set ShellWSH = WScript.CreateObject("WScript.Shell")
MSG_String = "cmd /C pm2.bat"
Ret = ShellWSH.Run (MSG_String,0,False)