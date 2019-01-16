PATH=%PATH%;%WSDK81%\bin\x86

rem sign using SHA-1
signtool sign /v /sha1 036BD383857B38A89D5DC5DFE5821CD1B942E38E /ac Thawt_CodeSigning_CA.crt /fd sha1 /t http://timestamp.verisign.com/scripts/timestamp.dll Release\VcFixBoot.exe x64\Release\VcFixBoot64.exe

rem sign using SHA-256
signtool sign /v /sha1 04141E4EA6D9343CEC994F6C099DC09BDD8937C9 /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /as /fd sha256 /tr http://timestamp.globalsign.com/?signature=sha2 /td SHA256 Release\VcFixBoot.exe x64\Release\VcFixBoot64.exe

pause
