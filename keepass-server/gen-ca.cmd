@echo off
setlocal
set "OUT_DIR=C:\temp\certs"
set "JAVA_HOME=D:\Applications\Java\jdk1.7.0_71"
set "KEYTOOL=%JAVA_HOME%\bin\keytool.exe"
set "PASS=changeit"
set "OUT_KEYSTORE=%OUT_DIR%\ca.jks"

REM ## ROOT CA ##
%KEYTOOL% -noprompt -genkeypair -keyalg RSA -keysize 2048 -alias ca0 -validity 18000 -dname cn=ca0 -ext "BasicConstraints:critical=ca:true,pathlen:10000" -keystore %OUT_KEYSTORE% -storepass %PASS% -keypass %PASS%
%KEYTOOL% -noprompt -genkeypair -keyalg RSA -keysize 2048 -alias ca1 -validity 360 -dname cn=ca1 -keystore %OUT_KEYSTORE% -storepass %PASS% -keypass %PASS%


IF EXIST %OUT_KEYSTORE%.csreq del /F %OUT_KEYSTORE%.csreq
IF EXIST %OUT_KEYSTORE%.csresp del /F %OUT_KEYSTORE%.csresp

%KEYTOOL% -certreq -keystore %OUT_KEYSTORE% -storepass %PASS% -alias ca1 -file %OUT_KEYSTORE%.csreq
%KEYTOOL% -gencert -keystore %OUT_KEYSTORE% -storepass %PASS% -alias ca0 -validity 365 -ext "BasicConstraints:critical=ca:true,pathlen:10000" -ext "KeyUsage:critical=keyCertSign" -ext "SubjectAlternativeName=dns:ca1" -infile %OUT_KEYSTORE%.csreq -outfile %OUT_KEYSTORE%.csresp
%KEYTOOL% -importcert -keystore %OUT_KEYSTORE% -storepass %PASS% -alias ca1 -file %OUT_KEYSTORE%.csresp

IF EXIST %OUT_KEYSTORE%.csreq del /F %OUT_KEYSTORE%.csreq
IF EXIST %OUT_KEYSTORE%.csresp del /F %OUT_KEYSTORE%.csresp
endlocal