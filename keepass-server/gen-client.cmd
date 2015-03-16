@echo off
setlocal
set "OUT_DIR=C:\temp\certs"
set "JAVA_HOME=D:\Applications\Java\jdk1.7.0_71"
set "KEYTOOL=%JAVA_HOME%\bin\keytool.exe"
set "PASS=changeit"
set "SIGN_ALIAS=ca1"
set "SIGN_KEYSTORE=%OUT_DIR%\ca.jks"
set "SIGN_PASS=%PASS%"

set "CERT_HOSTNAME=localhost"
set "CERT_ALIAS=cli_%CERT_HOSTNAME%"
set "CERT_CN=%CERT_HOSTNAME%"
set "OUT_KEYSTORE=%OUT_DIR%\keystore-%CERT_ALIAS%.jks"
set "OUT_CERT=%OUT_DIR%\keystore-%CERT_ALIAS%.crt"

IF EXIST %OUT_KEYSTORE% del /F %OUT_KEYSTORE%
IF EXIST %OUT_KEYSTORE%.csreq del /F %OUT_KEYSTORE%.csreq
IF EXIST %OUT_KEYSTORE%.csresp del /F %OUT_KEYSTORE%.csresp

%KEYTOOL% -noprompt -genkeypair -keyalg RSA -keysize 2048 -alias %CERT_ALIAS% -validity 360 -dname "cn=%CERT_CN%" -keystore %OUT_KEYSTORE% -storepass %PASS% -keypass %PASS%
%KEYTOOL% -certreq -keystore %OUT_KEYSTORE% -storepass %PASS% -alias %CERT_ALIAS% -file %OUT_KEYSTORE%.csreq
%KEYTOOL% -gencert -keystore %SIGN_KEYSTORE% -storepass %SIGN_PASS% -alias %SIGN_ALIAS% -validity 365 -ext "SubjectAlternativeName=dns:%CERT_CN%" -ext "KeyUsage:critical=digitalSignature,keyEncipherment" -ext "ExtendedKeyUsage=clientAuth" -infile %OUT_KEYSTORE%.csreq -outfile %OUT_KEYSTORE%.csresp
%KEYTOOL% -noprompt -importkeystore -srckeystore %SIGN_KEYSTORE% -srcstorepass %SIGN_PASS% -destkeystore %OUT_KEYSTORE% -deststorepass %PASS%
%KEYTOOL% -importcert -keystore %OUT_KEYSTORE% -storepass %PASS% -alias %CERT_ALIAS% -file %OUT_KEYSTORE%.csresp
%KEYTOOL% -exportcert -keystore %OUT_KEYSTORE% -storepass %PASS% -alias %CERT_ALIAS% -file %OUT_CERT% -rfc

IF EXIST %OUT_KEYSTORE%.csreq del /F %OUT_KEYSTORE%.csreq
IF EXIST %OUT_KEYSTORE%.csresp del /F %OUT_KEYSTORE%.csresp

endlocal