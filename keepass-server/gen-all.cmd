set "OUT_DIR=C:\temp\certs"
set "KEYTOOL=%JAVA_HOME%\bin\keytool.exe"
set "PASS=changeit"

REM ## ROOT CA ##
%KEYTOOL% -noprompt -genkeypair -keyalg RSA -keysize 2048 -alias ca0 -validity 18000 -dname cn=ca0 -ext BasicConstraints:critical=ca:truepathlen:10000 -keystore %OUT_DIR%\keystore.jks -storepass %PASS% -keypass %PASS%
%KEYTOOL% -noprompt -genkeypair -keyalg RSA -keysize 2048 -alias ca1 -validity 360 -dname cn=ca1 -ext BasicConstraints:critical=ca:truepathlen:10000 -keystore %OUT_DIR%\keystore.jks -storepass %PASS% -keypass %PASS%

del %OUT_DIR%\keystore.jks.csreq
%KEYTOOL% -certreq -keystore %OUT_DIR%\keystore.jks -storepass %PASS% -alias ca1 -file %OUT_DIR%\keystore.jks.csreq
%KEYTOOL% -gencert -keystore %OUT_DIR%\keystore.jks -storepass %PASS% -alias ca0 -validity 365 -ext BasicConstraints:critical=ca:truepathlen:10000 -ext "KeyUsage:critical=keyCertSign" -ext "SubjectAlternativeName=dns:ca1" -infile %OUT_DIR%\keystore.jks.csreq -outfile %OUT_DIR%\keystore.jks.csresp
%KEYTOOL% -importcert -keystore %OUT_DIR%\keystore.jks -storepass %PASS% -alias ca1 -file %OUT_DIR%\keystore.jks.csresp


%KEYTOOL% -noprompt -genkeypair -keyalg RSA -keysize 2048 -alias localhost -validity 360 -dname cn=localhost -keystore %OUT_DIR%\keystore.server.jks -storepass %PASS% -keypass %PASS%
%KEYTOOL% -noprompt -importcert -keystore %OUT_DIR%\keystore.server.jks -storepass %PASS% -alias ca0 -file %OUT_DIR%\keystore.ca0.crt -trustcacerts
%KEYTOOL% -certreq -keystore %OUT_DIR%\keystore.server.jks -storepass %PASS% -alias localhost -file %OUT_DIR%\keystore.server.jks.csreq
%KEYTOOL% -gencert -keystore %OUT_DIR%\keystore.jks -storepass %PASS% -alias ca1 -validity 365 -ext SubjectAlternativeName=dns:localhost -ext KeyUsage:critical=keyEnciphermentdigitalSignature -ext ExtendedKeyUsage=serverAuthclientAuth -infile %OUT_DIR%\keystore.server.jks.csreq -outfile %OUT_DIR%\keystore.server.jks.csresp
%KEYTOOL% -importcert -keystore %OUT_DIR%\keystore.server.jks -storepass %PASS% -alias localhost -file %OUT_DIR%\keystore.server.jks.csresp
%KEYTOOL% -exportcert -keystore %OUT_DIR%\keystore.server.jks -storepass %PASS% -alias localhost -file %OUT_DIR%\keystore.server.crt -rfc

%KEYTOOL% -exportcert -keystore %OUT_DIR%\keystore.jks -storepass %PASS% -alias ca1 -file %OUT_DIR%\keystore.ca1.crt -rfc
%KEYTOOL% -noprompt -importcert -keystore %OUT_DIR%\keystore.truststore.jks -storepass %PASS% -alias ca0 -file %OUT_DIR%\keystore.ca0.crt -trustcacerts
%KEYTOOL% -noprompt -importcert -keystore %OUT_DIR%\keystore.truststore.jks -storepass %PASS% -alias ca1 -file %OUT_DIR%\keystore.ca1.crt
%KEYTOOL% -noprompt -importcert -keystore %OUT_DIR%\keystore.server.jks -storepass %PASS% -alias ca0 -file %OUT_DIR%\keystore.ca0.crt -trustcacerts
%KEYTOOL% -noprompt -importcert -keystore %OUT_DIR%\keystore.server.jks -storepass %PASS% -alias ca1 -file %OUT_DIR%\keystore.ca1.crt
%KEYTOOL% -noprompt -importkeystore -srckeystore %OUT_DIR%\keystore.truststore.jks -srcstorepass %PASS% -destkeystore %OUT_DIR%\keystore.server.jks -deststorepass %PASS%
%KEYTOOL% -noprompt -genkeypair -keyalg RSA -keysize 2048 -alias client -validity 360 -dname cn=MY.CLIENT ou=JavaSoft o=Sun c=US -keystore %OUT_DIR%\keystore.client.jks -storepass %PASS% -keypass %PASS%
%KEYTOOL% -noprompt -importcert -keystore %OUT_DIR%\keystore.client.jks -storepass %PASS% -alias ca0 -file %OUT_DIR%\keystore.ca0.crt -trustcacerts
%KEYTOOL% -certreq -keystore %OUT_DIR%\keystore.client.jks -storepass %PASS% -alias client -file %OUT_DIR%\keystore.client.jks.csreq
%KEYTOOL% -gencert -keystore %OUT_DIR%\keystore.jks -storepass %PASS% -alias ca1 -validity 365 -ext SubjectAlternativeName=dns:localhost -ext KeyUsage:critical=digitalSignaturekeyEncipherment -ext ExtendedKeyUsage=clientAuth -infile %OUT_DIR%\keystore.client.jks.csreq -outfile %OUT_DIR%\keystore.client.jks.csresp
%KEYTOOL% -importcert -keystore %OUT_DIR%\keystore.client.jks -storepass %PASS% -alias client -file %OUT_DIR%\keystore.client.jks.csresp
%KEYTOOL% -noprompt -importkeystore -srckeystore %OUT_DIR%\keystore.client.jks -srcstorepass %PASS% -destkeystore %OUT_DIR%\keystore.client.p12 -deststorepass %PASS% -deststoretype PKCS12
