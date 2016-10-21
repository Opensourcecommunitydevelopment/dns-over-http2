Set ShellWSH = WScript.CreateObject("WScript.Shell")
MSG_String = "powershell /C ./dns-over-http2.ps1"
Ret = ShellWSH.Run (MSG_String,0,False)