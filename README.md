{ "version": "v2.8.0", "id": "f0e16c9a-a3ea-4e58-8094-5625f8734812",
"repositoryID": "00000000-0000-0000-0000-000000000000",
"repositoryName": "","workspaceID":
"00000000-0000-0000-0000-000000000000", "workspaceName": "","status":
"success", "errors": "","createdAt": "2023-09-20T14:31:56.101037249Z",
"finishedAt": "2023-09-20T14:31:58.191507125Z",
"analysisVulnerabilities": \[ { "vulnerabilityID":
"00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191514326Z", "vulnerabilities": {
"vulnerabilityID": "a383d7ca-3d8a-45e9-8214-570e7ba549f8", "line": "38",
"column": "16", "confidence": "MEDIUM", "file": "C#/Accesso-DB.cs",
"code": "var password = \"password123\";", "details": "(1/1) \* Possible
vulnerability detected: Hard-coded password`\nThe `{=tex}software
contains hard-coded credentials, such as a password or cryptographic
key, which it uses for its own inbound authentication, outbound
communication to external components, or encryption of internal data.
For more information checkout the CWE-798
(https://cwe.mitre.org/data/definitions/798.html) advisory.",
"securityTool": "HorusecEngine", "language": "Leaks", "severity":
"CRITICAL", "type": "Vulnerability", "commitAuthor": "-", "commitEmail":
"-", "commitHash": "-", "commitMessage": "-", "commitDate": "-",
"rule_id": "HS-LEAKS-26", "vulnHash":
"a2d8ba6d39e62e27adb9344a8817013483e5e2b1b01901fae9732808081c9768",
"deprecatedHashes": \[
"3c7e13a211af5a5c4db80fdb418b27615e9a2ad7ece794b6b4ecc6a10d10c002",
"8d4e58acc406d9c663c6863123824a3db4302630370814dd93033f247d19e3e8" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191515326Z", "vulnerabilities": {
"vulnerabilityID": "15f7980a-94b7-43a7-872c-00a3e16497cc", "line": "6",
"column": "4", "confidence": "MEDIUM", "file": "Python/Accesso-DB.py",
"code": "app.secret_key = 'your_secret_key' \# Cambia questa chiave
segreta", "details": "(1/1) \* Possible vulnerability detected:
Potential Hard-coded credential`\nThe `{=tex}software contains
hard-coded credentials, such as a password or cryptographic key, which
it uses for its own inbound authentication, outbound communication to
external components, or encryption of internal data. For more
information checkout the CWE-798
(https://cwe.mitre.org/data/definitions/798.html) advisory.",
"securityTool": "HorusecEngine", "language": "Leaks", "severity":
"CRITICAL", "type": "Vulnerability", "commitAuthor": "-", "commitEmail":
"-", "commitHash": "-", "commitMessage": "-", "commitDate": "-",
"rule_id": "HS-LEAKS-25", "vulnHash":
"2486aa9c739a533725aefc941863e9b2c0a5c2b9cb9e3030f698e9c810cd1c0d",
"deprecatedHashes": \[
"ffbabdf157236ca88a399953158e9fbbe284c769aef575275c7ce6e3206d87dd",
"57ef3dcf82d1f0d4afeb996b25a80529a45646419fcb80f24b446e2fc524a311" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191516426Z", "vulnerabilities": {
"vulnerabilityID": "4164fcf8-25c6-4be4-b19f-504ea810fa84", "line": "44",
"column": "73", "confidence": "MEDIUM", "file":
"exercises/01-sql-injection.md", "code": "password\":\"password\"}'
'http://localhost:8080/login'", "details": "(1/1) \* Possible
vulnerability detected: Hard-coded password`\nThe `{=tex}software
contains hard-coded credentials, such as a password or cryptographic
key, which it uses for its own inbound authentication, outbound
communication to external components, or encryption of internal data.
For more information checkout the CWE-798
(https://cwe.mitre.org/data/definitions/798.html) advisory.",
"securityTool": "HorusecEngine", "language": "Leaks", "severity":
"CRITICAL", "type": "Vulnerability", "commitAuthor": "-", "commitEmail":
"-", "commitHash": "-", "commitMessage": "-", "commitDate": "-",
"rule_id": "HS-LEAKS-26", "vulnHash":
"accbec0cfef2b9bf4e5246992a5bf3f295aa84fc19ef3fc43b7d8b38caf0bf98",
"deprecatedHashes": \[
"a6e0fd573f82ff3e1a5b9b5dd417f2e4683446ab0d60695e462f7ea7b9720124",
"e355999de739c180499198fb154cba690ec5b71bc201af954099ec6e1ffcc4fd" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191517626Z", "vulnerabilities": {
"vulnerabilityID": "380dcc33-bc02-4efc-971f-27a3691d13ae", "line": "61",
"column": "77", "confidence": "MEDIUM", "file":
"exercises/01-sql-injection.md", "code": "ssword\":\"password\"}'
'http://localhost:8080/login' \| jq .", "details": "(1/1) \* Possible
vulnerability detected: Hard-coded password`\nThe `{=tex}software
contains hard-coded credentials, such as a password or cryptographic
key, which it uses for its own inbound authentication, outbound
communication to external components, or encryption of internal data.
For more information checkout the CWE-798
(https://cwe.mitre.org/data/definitions/798.html) advisory.",
"securityTool": "HorusecEngine", "language": "Leaks", "severity":
"CRITICAL", "type": "Vulnerability", "commitAuthor": "-", "commitEmail":
"-", "commitHash": "-", "commitMessage": "-", "commitDate": "-",
"rule_id": "HS-LEAKS-26", "vulnHash":
"197755c4c155fd2b73a9ad78c442e33baac97e8434fbb587db522e6adf2deff2",
"deprecatedHashes": \[
"48f0fd02527783cad981acb160f826e837075728eff515751a72bd66253b9751",
"a0eddc9e0f37d39a0e42d5c78423a03ad415981602faa62288c35c8cf9904a8b" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191508425Z", "vulnerabilities": {
"vulnerabilityID": "989242b4-b7a7-45db-aebb-6f698ae9473c", "line": "15",
"column": "6", "confidence": "HIGH", "file": "client/js/login.js",
"code": "alert(\"Whoops, try again\");", "details": "(1/1) \* Possible
vulnerability detected: Alert statements should not be
used`\nalert`{=tex}(...) as well as confirm(...) and prompt(...) can be
useful for debugging during development, but in production mode this
kind of pop-up could expose sensitive information to attackers, and
should never be displayed. For more information checkout the CWE-489
(https://cwe.mitre.org/data/definitions/489.html) advisory.",
"securityTool": "HorusecEngine", "language": "JavaScript", "severity":
"HIGH", "type": "Vulnerability", "commitAuthor": "-", "commitEmail":
"-", "commitHash": "-", "commitMessage": "-", "commitDate": "-",
"rule_id": "HS-JAVASCRIPT-16", "vulnHash":
"87b8e29fc55177d5e8b6c3c782fbd36c4046dffdcb6e2883aed96e19f1cef4f8",
"deprecatedHashes": \[
"6c4b621a77c454e5a2108c25257f0d4d4e7e4e3b6b78f84f87a75a635e474ef0",
"dbfa3e4ea283b884f4e4d47b1e84aea2a4c7bd0e63983e229a791cb60ddbdaad" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191512025Z", "vulnerabilities": {
"vulnerabilityID": "7b7ac135-2717-4705-b89a-661647444a3d", "line": "55",
"column": "4", "confidence": "HIGH", "file": "client/js/index.js",
"code": "alert(\"Goodbye!\");", "details": "(1/1) \* Possible
vulnerability detected: Alert statements should not be
used`\nalert`{=tex}(...) as well as confirm(...) and prompt(...) can be
useful for debugging during development, but in production mode this
kind of pop-up could expose sensitive information to attackers, and
should never be displayed. For more information checkout the CWE-489
(https://cwe.mitre.org/data/definitions/489.html) advisory.",
"securityTool": "HorusecEngine", "language": "JavaScript", "severity":
"HIGH", "type": "Vulnerability", "commitAuthor": "-", "commitEmail":
"-", "commitHash": "-", "commitMessage": "-", "commitDate": "-",
"rule_id": "HS-JAVASCRIPT-16", "vulnHash":
"2ce4802c561faf222704fc939424458c9692c10532a53808706bd5bde55ee702",
"deprecatedHashes": \[
"7e9a52dd27636fc3a3a37490901514850be08e845f88a68a010432cf4e459d05",
"dccada7c53d40e98a4341fc89ca45762d34b1134d70c6d92d0f08387ab76527d" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191518726Z", "vulnerabilities": {
"vulnerabilityID": "48f1dd37-2173-4f26-8bff-c7a24d86be08", "line": "21",
"column": "36", "confidence": "LOW", "file":
"src/main/java/com/scalesec/vulnado/LoginController.java", "code": "if
(Postgres.md5(input.password).equals(user.hashedPassword)) {",
"details": "(1/1) \* Possible vulnerability detected: Unsafe hash
equals`\nAn `{=tex}attacker might be able to detect the value of the
secret hash due to the exposure of comparison timing. When the functions
Arrays.equals() or String.equals() are called, they will exit earlier if
fewer bytes are matched. For more information checkout the CWE-704
(https://cwe.mitre.org/data/definitions/704.html) advisory.",
"securityTool": "HorusecEngine", "language": "Java", "severity": "HIGH",
"type": "Vulnerability", "commitAuthor": "-", "commitEmail": "-",
"commitHash": "-", "commitMessage": "-", "commitDate": "-", "rule_id":
"HS-JAVA-145", "vulnHash":
"6d21c4f93486ef8f40c7b4d36dae11cba26284c394bd8958f311639b1d66b5db",
"deprecatedHashes": \[
"52abf513f6949456bd0f3d730f0a2df94e2d5abb98c9d7cf2d4f5876fc358760",
"a734ae48a87fa1a518a4d9edc07ba75f2fb89f775f0991e56e03d434e273e266" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191519826Z", "vulnerabilities": {
"vulnerabilityID": "bc094bdf-be3a-4196-8e1c-391f9b972b70", "line": "31",
"column": "6", "confidence": "LOW", "file":
"src/main/java/com/scalesec/vulnado/Comment.java", "code": "} catch
(Exception e) {", "details": "(1/1) \* Possible vulnerability detected:
Information Exposure Through An Error Message`\nThe `{=tex}sensitive
information may be valuable information on its own (such as a password),
or it may be useful for launching other, more deadly attacks. For more
information checkout the CWE-209
(https://cwe.mitre.org/data/definitions/209.html) advisory.",
"securityTool": "HorusecEngine", "language": "Java", "severity": "HIGH",
"type": "Vulnerability", "commitAuthor": "-", "commitEmail": "-",
"commitHash": "-", "commitMessage": "-", "commitDate": "-", "rule_id":
"HS-JAVA-63", "vulnHash":
"69ce26adfe66e5987f6bf002527169639ec5c13d844dbce79e86a810e44e3b10",
"deprecatedHashes": \[
"d1ab501e8d074b6fbdd9ba18ae0ff1319b5639f15742727d8c16489e18a54b7c",
"65a32c3a27236ff3e50e88898efc4cc454efbb8d8e9f7539752b73a345fdede8" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191522126Z", "vulnerabilities": {
"vulnerabilityID": "312260cb-7e2f-4fe1-b6d9-83b53272e0da", "line": "57",
"column": "6", "confidence": "LOW", "file":
"src/main/java/com/scalesec/vulnado/User.java", "code": "} catch
(Exception e) {", "details": "(1/1) \* Possible vulnerability detected:
Information Exposure Through An Error Message`\nThe `{=tex}sensitive
information may be valuable information on its own (such as a password),
or it may be useful for launching other, more deadly attacks. For more
information checkout the CWE-209
(https://cwe.mitre.org/data/definitions/209.html) advisory.",
"securityTool": "HorusecEngine", "language": "Java", "severity": "HIGH",
"type": "Vulnerability", "commitAuthor": "-", "commitEmail": "-",
"commitHash": "-", "commitMessage": "-", "commitDate": "-", "rule_id":
"HS-JAVA-63", "vulnHash":
"a825caac7ba6a6b0176a8b89a0af675627fa622bd8e792842b323930ce0473c1",
"deprecatedHashes": \[
"fc688d5c01b580ffa63f60689686f2ae657aea3570efc1bf5ab06d5959ef4447",
"074b69e2b05b87bdeaa97deaf0b27749ffbe95d0c60ed2d27cd63f8670ec4626" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191523326Z", "vulnerabilities": {
"vulnerabilityID": "36204d00-7685-457c-9aeb-8c2409c8f56c", "line": "10",
"column": "7", "confidence": "LOW", "file":
"src/main/java/com/scalesec/vulnado/User.java", "code": "import
javax.crypto.SecretKey;", "details": "(1/1) \* Possible vulnerability
detected: Crypto import`\n `{=tex}Crypto import", "securityTool":
"HorusecEngine", "language": "Java", "severity": "HIGH", "type":
"Vulnerability", "commitAuthor": "-", "commitEmail": "-", "commitHash":
"-", "commitMessage": "-", "commitDate": "-", "rule_id": "HS-JAVA-123",
"vulnHash":
"7439e31fa15d3c9ec628297defd507c111fd615f3cb32d701a59401d0378e982",
"deprecatedHashes": \[
"d8eff110cdba0d2bf35de82aa02d1a5ab1c7f367f2a552a57983e25e32b718a7",
"fa96a28de70691efbb0eccb831d05ec5cea8520b4e3e5e7836c49e61d2422118" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191524326Z", "vulnerabilities": {
"vulnerabilityID": "ce172068-d611-49ef-a9dd-5d23b05565a9", "line": "47",
"column": "22", "confidence": "LOW", "file":
"src/main/java/com/scalesec/vulnado/User.java", "code": "String query =
\"select \* from users where username = '\" + un + \"' limit 1\";",
"details": "(1/1) \* Possible vulnerability detected: SQL
Injection`\nThe `{=tex}input values included in SQL queries need to be
passed in safely. Bind variables in prepared statements can be used to
easily mitigate the risk of SQL injection. Alternatively to prepare
statements, each parameter can be escaped manually. For more information
checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
advisory.", "securityTool": "HorusecEngine", "language": "Java",
"severity": "HIGH", "type": "Vulnerability", "commitAuthor": "-",
"commitEmail": "-", "commitHash": "-", "commitMessage": "-",
"commitDate": "-", "rule_id": "HS-JAVA-134", "vulnHash":
"9a1ad861aca6a028b62bcb52a6c0cc2be959c2d3bc8b488b3d3c95c83d97aacd",
"deprecatedHashes": \[
"28fc7b5fb3dc6b4b07309efb9aa9904561fb3506a4f0a3f4270981c0d8b638ce",
"be2aec3219f0c795367d846c85b513d936149be3b8abcfcf849cf03c742eb113" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191528626Z", "vulnerabilities": {
"vulnerabilityID": "945bca90-1147-4943-93fe-382b190fbad5", "line": "24",
"column": "10", "confidence": "LOW", "file":
"src/main/java/com/scalesec/vulnado/Postgres.java", "code": "} catch
(Exception e) {", "details": "(1/1) \* Possible vulnerability detected:
Information Exposure Through An Error Message`\nThe `{=tex}sensitive
information may be valuable information on its own (such as a password),
or it may be useful for launching other, more deadly attacks. For more
information checkout the CWE-209
(https://cwe.mitre.org/data/definitions/209.html) advisory.",
"securityTool": "HorusecEngine", "language": "Java", "severity": "HIGH",
"type": "Vulnerability", "commitAuthor": "-", "commitEmail": "-",
"commitHash": "-", "commitMessage": "-", "commitDate": "-", "rule_id":
"HS-JAVA-63", "vulnHash":
"e1d823b0b0334786999b0e936095475ab2828ffedc2805c3a6742c29e378fb2a",
"deprecatedHashes": \[
"8061f4e3d63a7005f71c497222079dcfe5595ff7b9b2a1547413b02e28feef2e",
"2168ed7180aa5d6e11c4db997abda527b9ec19fe3bc2e826eeebe3c0beafac85" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191529827Z", "vulnerabilities": {
"vulnerabilityID": "4e4792e1-09ea-44eb-9de2-2eaaa3f6108b", "line": "67",
"column": "31", "confidence": "LOW", "file":
"src/main/java/com/scalesec/vulnado/Postgres.java", "code":
"MessageDigest md = MessageDigest.getInstance(\"MD5\");", "details":
"(1/1) \* Possible vulnerability detected: Weak Cryptographic Hash
Function used`\nUsing `{=tex}a weak CHF pose a threat to your
application security since it can be vulnerable to a number of attacks
that could lead to data leaking, improper access of features and
resources of your infrastructure and even rogue sessions. For more
information checkout the CWE-327
(https://cwe.mitre.org/data/definitions/327.html) advisory.",
"securityTool": "HorusecEngine", "language": "Java", "severity": "HIGH",
"type": "Vulnerability", "commitAuthor": "-", "commitEmail": "-",
"commitHash": "-", "commitMessage": "-", "commitDate": "-", "rule_id":
"HS-JAVA-111", "vulnHash":
"6a89eef0d2e38e08adb8a3455b71624e14cc977f1d6efcfade11dcca9a51a1ea",
"deprecatedHashes": \[
"f9f8254a398a2ba9f2e498dc6980e3e5013604090fd39c99fd304088f546b2c8",
"74ecd946de05e15cf4d13d6c8e393c935ab80487a70a0ecebeaaf923d32ae74a" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191534327Z", "vulnerabilities": {
"vulnerabilityID": "62e720b0-175c-4eaf-b50e-47f4979d0b7c", "line": "35",
"column": "3", "confidence": "LOW", "file": "pom.xml", "code":
"`\u0`{=tex}03cgroupId`\u0`{=tex}03eorg.postgresql`\u0`{=tex}03c/groupId`\u0`{=tex}03e",
"details": "(1/1) \* Possible vulnerability detected: Unchecked Class
Instantiation when providing Plugin Classes`\nCVE-2022`{=tex}-21724
pgjdbc instantiates plugin instances based on class names provided via
authenticationPluginClassName, sslhostnameverifier, socketFactory,
sslfactory, sslpasswordcallback connection properties. However, the
driver did not verify if the class implements the expected interface
before instantiating the class. The first impacted version is
REL9.4.1208 (it introduced socketFactory connection property) until
42.3.1. Please update to fixed versions \^42.2.25 or \^42.3.2. For more
information checkout the CVE-2022-21724
(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21724)
advisory.", "securityTool": "HorusecEngine", "language": "Java",
"severity": "HIGH", "type": "Vulnerability", "commitAuthor": "-",
"commitEmail": "-", "commitHash": "-", "commitMessage": "-",
"commitDate": "-", "rule_id": "HS-JAVA-151", "vulnHash":
"0b7354a96880c2b32086981194f0474de0da1cddecb9cb256972dccce5e5424c",
"deprecatedHashes": \[
"bd6c998f994b92540ed9b9a8ea257a01b6226223c89c82517fec51a67c583b47",
"d7c3aa707c95c6bdeba5afa63145bc117d085b1a138d54b9add8b2e372ee171e" \],
"securityToolVersion": "","securityToolInfoUri": "" } }, {
"vulnerabilityID": "00000000-0000-0000-0000-000000000000", "analysisID":
"f0e16c9a-a3ea-4e58-8094-5625f8734812", "createdAt":
"2023-09-20T14:31:58.191535627Z", "vulnerabilities": {
"vulnerabilityID": "2157e1cb-d35b-4839-be73-c07586cb5b6e", "line": "23",
"column": "6", "confidence": "LOW", "file":
"src/main/java/com/scalesec/vulnado/Cowsay.java", "code": "} catch
(Exception e) {", "details": "(1/1) \* Possible vulnerability detected:
Information Exposure Through An Error Message`\nThe `{=tex}sensitive
information may be valuable information on its own (such as a password),
or it may be useful for launching other, more deadly attacks. For more
information checkout the CWE-209
(https://cwe.mitre.org/data/definitions/209.html) advisory.",
"securityTool": "HorusecEngine", "language": "Java", "severity": "HIGH",
"type": "Vulnerability", "commitAuthor": "-", "commitEmail": "-",
"commitHash": "-", "commitMessage": "-", "commitDate": "-", "rule_id":
"HS-JAVA-63", "vulnHash":
"5469b95e0ae1aa074e65f1a0a47ef6914a663cecc7ff7891d00e21ec86588106",
"deprecatedHashes": \[
"add21ab1083092d9c83be0c1ff61365f740d4e30fb88555a34c8439516972d05",
"d2970d492f6a6eebee92760f7ee33e770b61a209c050e2fbb3797f6412c12b98" \],
"securityToolVersion": "","securityToolInfoUri": "" } } \] }
