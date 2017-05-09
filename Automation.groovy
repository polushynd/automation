/*
 Created by polushynd on 1/25/2017.
*/
import com.ixia.textmlserver.*
import groovy.io.FileType
import groovy.text.SimpleTemplateEngine
import com.github.sarxos.winreg.HKey
import com.github.sarxos.winreg.WindowsRegistry
import org.w3c.dom.DocumentType
import org.w3c.dom.NodeList
import org.xml.sax.InputSource
import javax.xml.transform.OutputKeys
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.prefs.Preferences
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import com.ixiasoft.utils.crypto.CryptoHelper;

class Automation {

    static String currentPath = System.getProperty("user.dir");
    static String propertyFilePath = "${currentPath}/properties.txt"
    static String osType
    static String pathToTomcat
    static Map prop = [:]
    public static jdk = "jdk1.8.0_121"
    public static glassfish_archive = 'glassfish-4.1.1.zip'
    public static glassfish_xmx = '-Xmx1024m';
    public static glassfish_xms =  '-Xms512m'
    public static tomcat_archive = 'apache-tomcat-7.0.75.zip'
    public static tomcat_xmx = '-Xmx1024m'
    public static tomcat_xms = '-Xms512m'
    public static tomcat_xmx_service = '--JvmMx=1024'
    public static tomcat_xms_service = '--JvmMs=512'


    public static String checkOS(){
        String osType = System.properties['os.name']
        if(osType == 'Linux'){
            osType = "linux"
            println "OS is detected: Linux"
            isAdmin()
        }
        else if(osType.contains("Windows")){
            osType = "windows"
            println "OS is detected: Windows"
            isAdmin()
            checkNetFramework()
        }
        else {
            println "ERROR: Cannot identify your OS: ${osType}"
            System.exit(127)
        }
        return osType
    }

     public static void isAdmin(){
        Preferences prefs = Preferences.systemRoot();
        PrintStream systemErr = System.err;
        // better synchronize to avoid problems with other threads that access System.err
        synchronized(systemErr){
            System.setErr(null);
            try{
                prefs.put("foo", "bar"); // SecurityException on Windows
                prefs.remove("foo");
                prefs.flush(); // BackingStoreException on Linux
                System.out.println("User has Administrator or root privileges")
            }catch(Exception e){
                System.out.println("ERROR: Please run the script as Administrator or root provileges")
                System.exit(127)
            }finally{
                System.setErr(systemErr);
            }
        }
    }

    public static void checkNetFramework(){
        try {
            List versions = []
            WindowsRegistry reg = WindowsRegistry.getInstance();
            String branch = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP";
            List<String> keys = reg.readStringSubKeys(HKey.HKLM, branch);
            keys.each {
                if (it.contains("v2.0") || it.contains("v3.0"))
                    versions << it
            }
            List values = []
            if (versions.size() == 2) {
                versions.each {
                    reg = WindowsRegistry.getInstance();
                    String tree = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\${it}";
                    values << reg.readString(HKey.HKLM, tree, "Version");
                }
            } else {
                println "ERROR: Please install .Net Framework 2.0 and 3.0"
                System.exit(127)
            }
            values.each {
                if (it != null) {
                    println ".Net Framework version ${it} was found"
                } else {
                    println "ERROR: Please install .Net Framework 2.0 and 3.0"
                    System.exit(127)
                }
            }
        }
        catch(e){
            println "ERROR: Cannot check .Net Framework version: ${e}"
            System.exit(127)
        }
    }

    public static Map propertiesSetup(){
        //Get all properties: properties.txt
        def propertiesFile = new File(propertyFilePath)
        String key, value
        if (propertiesFile.exists()) {
            propertiesFile.eachLine { line ->
                if(line.contains("=") && !line.startsWith("#")){
                    key = line.split("=")[0]
                    line = line.replace("${key}=","")
                    if(line.length() > 0){
                        value = line.replace("\\", "/")
                    }
                    else {
                        value = ""
                    }
                }
                prop.put(key.trim(), value.trim())
            }

            try {
                //todo Check for other value later
                int tPort = prop['TOMCAT_HTTP_PORT'].toInteger()
                if (tPort < 0 || tPort > 65536) {
                    println "ERROR: Please check properties.txt file (TOMCAT_HTTP_PORT = ${tPort})"
                    System.exit(127)
                }
            }
            catch(e){
                println "ERROR: TOMCAT_HTTP_PORT is null"
                System.exit(127)
            }
        }
        else{
            println "ERROR: Property file does not exist."
            System.exit(127)
        }
        return prop
    }

    public static void addCert(String keystorePath, String certfile, char [] password){
        String alias = certfile.split("/")[-1]
        // Open keystore
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        File keystoreFile = new File(keystorePath);
        // Open cert
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream certstream = null;
        try {
            certstream = new FileInputStream(new File(certfile));
            Certificate certs = cf.generateCertificate(certstream);
            // Load the keystore contents
            FileInputStream ks = new FileInputStream(keystoreFile);
            keystore.load(ks, password);
            ks.close();
            // Add the certificate
            keystore.setCertificateEntry(alias, certs);
            // Save the new keystore contents
            FileOutputStream out = new FileOutputStream(keystoreFile);
            keystore.store(out, password);
            out.close();
        } finally {
            if (certstream != null) {
                certstream.close();
            }
        }
    }

    public static void addCerts(String pathToStore){
        try {
            def list = []
            String pathToCert
            def dir = new File("${prop["SSL_FOLDER"]}".replaceAll("\\\\", "/"))
            char[] password = "${prop["KEYSTORE_PASS"]}".toCharArray();
            dir.eachFileRecurse(FileType.FILES) { file ->
                list << file
            }
            if (list.size() > 0) {
                list.each {
                    pathToCert = it.toString().replaceAll("\\\\", "/")
                    pathToStore = new File(pathToStore).exists() ? pathToStore : pathToStore.replace(".jks", "")
                    //Add certificates into the store
                    addCert(pathToStore, pathToCert, password)
                }
            } else {
                println "ERROR: Cannot find any certificate file in ${pathToCert}"
                System.exit(127)
            }
        }
        catch(e){
            println "ERROR: Cannot add certificate to keystore"
            println e
            System.exit(127)
        }
    }

//get /system/conf/user.xml
    public static String getUserFile() throws Exception{
        ByteArrayOutputStream f
        try {
            String port = prop['PORT'];
            String host = prop['TEXTML_SERVER_HOST'];
            InetAddress addr = InetAddress.getByName(host)
            SocketAddress sockaddr = new InetSocketAddress(addr, Integer.parseInt(port));
            Socket socket = new Socket();
            int timeout = 10000;
            socket.connect(sockaddr, timeout);
            println "Textml port is available"
            HashMap params = new HashMap(1);
            params.put("instance", "TextmlServer");
            ClientServices cs = com.ixia.textmlserver.ClientServicesFactory.getInstance("CORBA", params);
            String decPass = new String()
            if( prop['APPSERVER_LOGIN_PASSWORD'].toString().startsWith(CryptoHelper.getMagic())){
                decPass = CryptoHelper.localDecrypt( prop['APPSERVER_LOGIN_PASSWORD'].substring( CryptoHelper.getMagic().length() ) )
            }
            else{
                decPass = prop['APPSERVER_LOGIN_PASSWORD']
            }
            cs.Login(prop['APPSERVER_LOGIN_DOMAIN'], prop['APPSERVER_LOGIN_NAME'], decPass);
            println "Connection to TEXTML Server was successful"
            IxiaServerServices ss = prop["TEXTML_SSL_ENABLE"] == "false" ? cs.ConnectServer("${host}:${port}") : cs.SecureConnectServer("${host}:${port}")
            IxiaDocBaseServices docbase = ss.ConnectDocBase(prop['DOCBASE_NAME']);
            println "Connection to the Content Store was successful"
            IxiaDocumentServices ds = docbase.DocumentServices();
            String[] documents = new String[1];
            documents[0] = "/system/conf/users.xml";
            f = new ByteArrayOutputStream();
            IxiaDocumentServices.Result[] result = ds.GetDocuments(documents, 2, 1);
            result[0].document.GetContent().SaveTo(f);
            String file = new String(f.toString());
            println "Getdocument /system/conf/users.xml was successful"
            ds.Release();
            docbase.Release();
            ss.Release();
            cs.Logout();
            return file;
        }
        catch(all){
            //Todo This should be split into multiple try catch to give a better error message
            println "ERROR:"
            println "Cannot connect to the DB: ${prop['DOCBASE_NAME']}, host: ${prop['TEXTML_SERVER_HOST']}"
            println "Verify that the properties APPSERVER_LOGIN_DOMAIN, APPSERVER_LOGIN_NAME, APPSERVER_LOGIN_PASSWORD have correct values"
            println all
            System.exit(127)
        }
        finally{
            if(f != null) {
                f.close()
            }
        }
    }

    public static void checkUserXML(){
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        docFactory.setAttribute("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
        Document doc = docBuilder.parse(new InputSource(new StringReader(getUserFile().replaceAll("\\<.*?\\?>","").replaceAll("[^\\x20-\\x7e]", ""))));
        doc.getDocumentElement().normalize();
        doc.setXmlStandalone(true);
        parserUserxml (doc, "${prop["APPSERVER_LOGIN_DOMAIN"]}", "${prop["APPSERVER_LOGIN_NAME"]}")
        parserUserxml (doc, "${prop["WEBCONFIG_LOGIN_DOMAIN"]}", "${prop["WEBCONFIG_LOGIN_NAME"]}")
    }

    public static String checkFolders(String dirD){
        File dir = new File(dirD);
        if(dir.exists()){
            println "ERROR: ${dirD} was found. Please remove ${dirD.split('/')[-1]} and run the script again"
            System.exit(127)
        }
    }

    public static String checkJDK(String ixiaPath){
        if (jdk.toString().contains(prop['JDK'].toString())) {
            File dir = new File("${ixiaPath}/${jdk}/bin");
            if (dir.exists()) {
                //If the JDK is already installed, if in SSL add the SSL certificate to it
                println "JDK: ${prop['JDK']} found, skip JDK copy"
                if(!"${prop["TEXTML_SSL_ENABLE"]}".contains("false")) {
                    addCerts("${ixiaPath}/${jdk}/jre/lib/security/cacerts")
                }
            } else {
                copyDir("${currentPath}/source/${osType}/${jdk}", "${ixiaPath}/${jdk}")
                if (osType.contains('linux')) {
                    executeCommand("chmod +x ${ixiaPath}/${jdk}/bin/java")
                    executeCommand("chmod +x ${ixiaPath}/${jdk}/bin/keytool")
                }
                //Delete the extra JAR that was present in source JDK and not needed in the destination JDK
                ['serializer-2.7.2.jar', 'windows-registry-util-0.2.jar', 'jacorb.jar', 'log4j-1.2.17.jar', 'slf4j-api-1.5.6.jar', 'slf4j-jdk14-1.5.6.jar', 'textmlserver.jar', 'textmlservercorba.jar', 'textmlservercorbaInterfaces.jar', 'ixiasoft-utils.jar'].each {
                    deleteFile("${ixiaPath}/${jdk}/jre/lib/ext/${it}")
                }
            }
        }
        else{
            jdk = prop["JDK"]
            File dir = new File("${ixiaPath}/${jdk}/bin")
            if (dir.exists()) {
                if(!"${prop["TEXTML_SSL_ENABLE"]}".contains("false")) {
                    addCerts("${ixiaPath}/${jdk}/jre/lib/security/cacerts")
                }
                println "JDK: ${jdk} found, continue..."
            }
            else{
                println "ERROR: Cannot find ${jdk} in ${ixiaPath} folder"
                System.exit(127);
            }
        }
    }

    public static void deleteFile(String someFile){
        new AntBuilder().delete(file:someFile,failonerror:true)
        //Todo Need to wrap this in case of error and print an error message
    }

    public static void copyDir(String sourceDir, destinationDir) {
        new AntBuilder().copy(todir: destinationDir) {
            fileset(dir: sourceDir, includes: "**")
            //Todo Need to wrap this in case of error and print an error message
        }
    }

    public static void copyFile(String sourceFile, String destinationFile) {
        println "Copy file ${sourceFile} to ${destinationFile}"
        new AntBuilder().copy( file:sourceFile,
                tofile: destinationFile)
        //Todo Need to wrap this in case of error and print an error message
    }

    public static void unzipDir(String sourceArchive, destFolder){
        new AntBuilder().unzip(  src: sourceArchive,
                dest: destFolder,  overwrite:"true");
        //Todo Need to wrap this in case of error and print an error message
    }

    public static void mkDir(String dirName){
        new AntBuilder().mkdir(dir:dirName)
        //Todo Need to wrap this in case of error and print an error message
    }

    public static appendText(String text, String fileName){
        def f = new File(fileName)
        f.append(System.getProperty("line.separator") + text)
        println "added line: ${text} at the end of ${fileName}"
        //Todo Need to wrap this in case of error and print an error message
    }

    public static replaceLine(String needle, String replacement, String fileName){
        new AntBuilder().replace(file: fileName, token: needle, value: replacement)
        //Todo Need to wrap this in case of error and print an error message
    }

//Todo Make only one execcommand with exti code
    public static executeCommand(String command){
        println "Execute the command: ${command}"
        def proc = command.execute();
        proc.waitForProcessOutput(System.out, System.err)
    }

    public static executeCommandWithCheck(String command, String error){
        println "Execute the command: ${command}"
        def proc = command.execute();
        String result = proc.text
        if (result.contains(error)){
            println "ERROR: ${result}"
            System.exit(127)
        }
        else{
            println "${result}"
        }
    }

    public static createGlassfishDomain(String ixiaPath, String asadmin){

        try {
            String pass = "${ixiaPath}/glassfish4/pass"
            executeCommand("${asadmin} delete-domain domain1")
            appendText("AS_ADMIN_PASSWORD=", "${pass}")
            appendText("AS_ADMIN_NEWPASSWORD=${prop['ADMIN_PASSWORD']}", "${pass}")
            executeCommandWithCheck("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} create-domain --adminport ${prop['ADMIN_PORT']} --instanceport ${prop["HTTP_PORT"]} ${prop["DOMAIN_NAME"]}", 'Try a different port number')
            executeCommand("${asadmin} start-domain ${prop["DOMAIN_NAME"]}")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} change-admin-password --domain_name ${prop['DOMAIN_NAME']}")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} delete-jvm-options -client")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} delete-jvm-options -Xmx512m")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} delete-jvm-options '-XX:MaxPermSize=192m'")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} create-jvm-options -server")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} create-jvm-options ${glassfish_xmx}")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} create-jvm-options ${glassfish_xms}")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} create-jvm-options -Djava.security.krb5.conf=\${com.sun.aas.instanceRoot}/config/krb5.ini")
            executeCommand("${asadmin} --user ${prop['ADMIN_USER']} --passwordfile ${pass} --port ${prop['ADMIN_PORT']} enable-secure-admin")
            executeCommandWithCheck("${asadmin} stop-domain ${prop["DOMAIN_NAME"]}", "123")
            if(!"${prop["TEXTML_SSL_ENABLE"]}".contains("false")) {
                String pathtoCacert = "${ixiaPath}/glassfish4/glassfish/domains/${prop["DOMAIN_NAME"]}/config/cacerts.jks"
                def cacerts = new File(pathtoCacert).exists() ? pathtoCacert : pathtoCacert.replace(".jks", "")
                addCerts(cacerts)
            }
        }
        catch(e){
            println "ERROR: ${e}"
            System.exit(127)
        }
    }

    public static checkDirectoriesAndSSL(String ixiaPath, String pathToCacerts){
        //Check if the folders of glassfish4, tomcat7 exist, if yes terminate
        checkFolders("${ixiaPath}/glassfish4")
        checkFolders(pathToTomcat)
        if("${prop['TEXTML_SSL_ENABLE']}".contains("false")){
            checkUserXML()
        }
        else{
            def cacerts = new File(pathToCacerts).exists() ? pathToCacerts : pathToCacerts.replace(".jks", "")
            addCerts(cacerts)
            checkUserXML()
        }
    }

    public static setupGlassFish(String ixiaPath, String asadmin){
        //unzip Glassfish4
        unzipDir("${currentPath}/source/${glassfish_archive}", ixiaPath)
        //append AS_JAVA value in file asenv.conf
        if(osType.contains('windows')) {
            appendText("set AS_JAVA=${ixiaPath.replace("/", "\\")}\\${jdk}", "${ixiaPath}/glassfish4/glassfish/config/asenv.bat")
        }
        else{
            appendText("AS_JAVA=\"${ixiaPath}/${jdk}\"", "${ixiaPath}/glassfish4/glassfish/config/asenv.conf")
        }
        if(osType.contains('linux')){
            executeCommand("chmod +x ${asadmin}")
        }
        //create glassfish domain
        createGlassfishDomain(ixiaPath, asadmin)
    }

    public static setupTomcat(String ixiaPath, String osType){
        //unzip Tomcat
        unzipDir("${currentPath}/source/${tomcat_archive}", ixiaPath)
        if(osType.contains('linux')){
            appendText('#!/bin/sh', "${pathToTomcat}/bin/setenv.sh")
            appendText("export JRE_HOME=\"${ixiaPath}/${jdk}\"", "${pathToTomcat}/bin/setenv.sh")
            appendText("export JAVA_OPTS=\"${tomcat_xmx} ${tomcat_xms} -Djava.security.krb5.conf=\"${pathToTomcat}/conf/krb5.ini\" -Djava.security.auth.login.config=\"${pathToTomcat}/conf/login.conf\"\"", "${pathToTomcat}/bin/setenv.sh")
            executeCommand("chmod +x ${pathToTomcat}/bin/setenv.sh")
            executeCommand("chmod +x ${pathToTomcat}/bin/startup.sh")
            executeCommand("chmod +x ${pathToTomcat}/bin/shutdown.sh")
            executeCommand("chmod +x ${pathToTomcat}/bin/catalina.sh")
        }
        else{
            appendText('@echo off', "${pathToTomcat}/bin/setenv.bat")
            appendText("set JRE_HOME=${ixiaPath}/${jdk}", "${pathToTomcat}/bin/setenv.bat")
            appendText("set JAVA_OPTS=${tomcat_xmx} ${tomcat_xms} -Djava.security.krb5.conf=\"${pathToTomcat}/conf/krb5.ini\" -Djava.security.auth.login.config=\"${pathToTomcat}/conf/login.conf\"", "${pathToTomcat}/bin/setenv.bat")
        }
        //set http Port and Timeout
        replaceLine("<Connector port=\"8080\"", "<Connector port=\"${prop['TOMCAT_HTTP_PORT']}\"",  "${pathToTomcat}/conf/server.xml")
        replaceLine("<session-timeout>30", "<session-timeout>${prop['SESSION_TIMEOUT']}",  "${pathToTomcat}/conf/web.xml")
        //add Tomcat user
        replaceLine("</tomcat-users>", "<user username=\"${prop["TOMCAT_USER"]}\" password=\"${prop["TOMCAT_PASSWORD"]}\" roles=\"manager-gui,manager-script,manager-jmx,manager-status,admin-gui,admin-script\"/>\n</tomcat-users>",
                "${pathToTomcat}/conf/tomcat-users.xml")
    }

    public static void setupWindowsServices(String asadmin, String ixiaPath){
        //setup Glassfish
        String serviceNameGlassfish = prop['GLASSFISH_SERVICE_NAME'.replaceAll(" ", "_")]
        executeCommand("${asadmin} create-service --name ${serviceNameGlassfish}")
        executeCommand("sc config ${serviceNameGlassfish} DisplayName= \"${prop['GLASSFISH_DISPLAY_NAME']}\"")
        executeCommand("sc start  ${serviceNameGlassfish}")
        //setup Tomcat
        String serviceNameTomcat = prop['TOMCAT_SERVICE_NAME'.replaceAll(" ", "_")]
        executeCommand("cmd /c ${pathToTomcat.split(':')[0]}: && cd ${pathToTomcat}/bin && ${pathToTomcat}/bin/service.bat install ${serviceNameTomcat}")
        executeCommand("${pathToTomcat}/bin/tomcat7.exe //US//${serviceNameTomcat} ++JvmOptions=\"-Djava.security.krb5.conf=\\\"${pathToTomcat}/conf/krb5.ini\\\";-Djava.security.auth.login.config=\\\"${pathToTomcat}/conf/login.conf\\\"\"")
        executeCommand("${pathToTomcat}/bin/tomcat7.exe //US//${serviceNameTomcat} ${tomcat_xmx_service}")
        executeCommand("${pathToTomcat}/bin/tomcat7.exe //US//${serviceNameTomcat} ${tomcat_xms_service}")
        executeCommand("sc config ${serviceNameTomcat} DisplayName= \"${prop['TOMCAT_DISPLAY_NAME']}\"")
        executeCommand("sc config \"${serviceNameTomcat}\" start= delayed-auto")
        executeCommand("sc config \"${serviceNameTomcat}\" depend= ${serviceNameGlassfish}")
        executeCommand("sc start ${serviceNameTomcat}")
    }

    public static void fileParser(String template, String destPath, Map binding ){
        def simple = new SimpleTemplateEngine()
        def source = new File(template).text
        def output = simple.createTemplate(source).make(binding).toString()
        appendText(output, destPath)
        executeCommand("chmod +x ${destPath}")
    }

    public static void setupLinuxServices(){
        String glassfishServiceName = prop['GLASSFISH_SERVICE_NAME'.replaceAll(" ", "_")]
        String tomcatServiceName = prop['TOMCAT_SERVICE_NAME'.replaceAll(" ", "_")]
        Map glass = [ixiaPath: prop['IXIASOFT_LINUX'], DOMAIN_NAME: prop['DOMAIN_NAME'], username: prop['SERVICE_RUN_AS'], processname: glassfishServiceName]
        fileParser("${currentPath}/source/linux/GlassFishInitTemplate", "/etc/init.d/${glassfishServiceName}", glass)
        Map tom = [pathToTomcat: pathToTomcat, username: prop['SERVICE_RUN_AS'], processname: tomcatServiceName]
        fileParser("${currentPath}/source/linux/TomcatInitTemplate", "/etc/init.d/${tomcatServiceName}", tom)
        executeCommand("chown -R ${ prop['SERVICE_RUN_AS']}:${prop['SERVICE_RUN_AS']} ${prop['IXIASOFT_LINUX']}/glassfish4")
        executeCommand("chown -R ${ prop['SERVICE_RUN_AS']}:${prop['SERVICE_RUN_AS']} ${pathToTomcat}")
        executeCommand("/etc/init.d/${glassfishServiceName} start")
        executeCommand("/etc/init.d/${tomcatServiceName} start")
        executeCommand("/sbin/chkconfig ${glassfishServiceName} on ")
        executeCommand("/sbin/chkconfig ${tomcatServiceName} on ")
    }

    public static void parseXml(String pathToFile, String app){
        File inputFile = new File(pathToFile);
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        docFactory.setAttribute("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
        Document doc = docBuilder.parse(inputFile);
        doc.setXmlStandalone(true);
        if(app=="glass") {
            doc = parseCMSAppServer(doc)
        }
        else{
            doc = parseWebconfig(doc)
        }
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(pathToFile));
        DocumentType doctype = doc.getDoctype();
        if(doctype != null) {
            transformer.setOutputProperty(OutputKeys.DOCTYPE_SYSTEM, doctype.getSystemId());
        }
        transformer.transform(source, result);
    }

    public static Document parseCMSAppServer(Document doc){
        Node nNode = doc.getElementsByTagName("textml-connection").item(0);
        if (nNode.getNodeType() == Node.ELEMENT_NODE) {
            Element eElement = (Element) nNode;
            eElement.setAttribute("address",prop['TEXTML_SERVER_HOST']);
            eElement.setAttribute("port", prop['PORT']);
            eElement.setAttribute("secure", "${prop['TEXTML_SSL_ENABLE']}".contains("false") ? "false" : "true");
            eElement.setAttribute("docbase", prop['DOCBASE_NAME']);
        }
        nNode = doc.getElementsByTagName("admin-login").item(0);
        if (nNode.getNodeType() == Node.ELEMENT_NODE) {
            Element eElement = (Element) nNode;
            eElement.setAttribute("domain", prop['APPSERVER_LOGIN_DOMAIN']);
            eElement.setAttribute("name", prop['APPSERVER_LOGIN_NAME']);
            eElement.setAttribute("password", prop['APPSERVER_LOGIN_PASSWORD']);
        }
        return doc;
    }

    public static Document parseWebconfig(Document doc) {
        Node nNode = doc.getElementsByTagName("properties").item(0);
        if (nNode.getNodeType() == Node.ELEMENT_NODE) {
            Element eElement = (Element) nNode;
            eElement.getElementsByTagName("entry").item(0).setTextContent(prop['WEBCONFIG_LOGIN_DOMAIN']);
            eElement.getElementsByTagName("entry").item(1).setTextContent(prop['WEBCONFIG_LOGIN_NAME']);
            eElement.getElementsByTagName("entry").item(2).setTextContent(prop['WEBCONFIG_LOGIN_PASSWORD']);
        }
        return doc;
    }

    public static void parserUserxml (Document doc, String domain, String username) {
        NodeList nList = doc.getElementsByTagName("user");
        for (int temp = 0; temp < nList.getLength(); temp++) {
            Node nNode = nList.item(temp);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {

                Element eElement = (Element) nNode;
                if(eElement.getElementsByTagName("domain").item(0).getTextContent().trim() == domain && eElement.getElementsByTagName("login").item(0).getTextContent().trim() == username){
                    println ("The user was found: ${eElement.getElementsByTagName("domain").item(0).getTextContent().trim()}/${eElement.getElementsByTagName("login").item(0).getTextContent().trim()}")
                    break;
                }
                else{
                    if(temp == nList.getLength()-1) {
                        println("ERROR: Cannot find the user: ${domain}/${username} in the Content Store")
                        System.exit(127)
                    }
                }
            }
        }
    }

    public static void main(String[]args) {
        println "*********************************************"
        println System.properties.find { it.key == "java.home" }
        println "*********************************************"
        //Setup properties and env
        osType = checkOS()
        prop = propertiesSetup()
        String ixiaPath = osType.contains('linux') ? prop["IXIASOFT_LINUX"] : prop["IXIASOFT_WINDOWS"]
        mkDir(ixiaPath)
        pathToTomcat = "${ixiaPath}/${tomcat_archive.replaceAll('.zip', '')}"
        String asadmin = osType.contains('linux') ? "${ixiaPath}/glassfish4/bin/asadmin" : "${ixiaPath}/glassfish4/bin/asadmin.bat"
        //install and setup JDK, glassfish and tomcat
        if(true) {
            //Check if glassfish and tomcat folder exist and Add the SSL certificate to the current JDK to allow to connect to TEXTML Server
            checkDirectoriesAndSSL(ixiaPath, "${currentPath}/source/${osType}/${jdk}/jre/lib/security/cacerts")
            //install JDK
            checkJDK(ixiaPath)
            //install glassfish
            setupGlassFish(ixiaPath, asadmin)
            //install tomcat
            setupTomcat(ixiaPath, osType)
        }
        //install web platform
        if(true) {
            //Glassfish config, log and ear
            copyFile("${currentPath}/dita-cms/glassfish/log4j.xml", "${ixiaPath}/glassfish4/glassfish/domains/${prop['DOMAIN_NAME']}/config/log4j.xml")
            copyFile("${currentPath}/krb5.ini", "${ixiaPath}/glassfish4/glassfish/domains/${prop['DOMAIN_NAME']}/config/krb5.ini")
            appendText(new File("${currentPath}/dita-cms/login.conf").text, "${ixiaPath}/glassfish4/glassfish/domains/${prop['DOMAIN_NAME']}/config/login.conf")
            copyFile("${currentPath}/dita-cms/glassfish/CMSAppServer.config", "${ixiaPath}/glassfish4/glassfish/domains/${prop['DOMAIN_NAME']}/config/CMSAppServer.config")
            parseXml("${ixiaPath}/glassfish4/glassfish/domains/${prop['DOMAIN_NAME']}/config/CMSAppServer.config", "glass")
            copyFile("${currentPath}/dita-cms/glassfish/cmsappserver.ear", "${ixiaPath}/glassfish4/glassfish/domains/${prop['DOMAIN_NAME']}/autodeploy/cmsappserver.ear")
            //Tomcat config, log and xeditor and ditacms
            mkDir("${pathToTomcat}/conf/ditacms")
            copyFile("${currentPath}/dita-cms/tomcat/webconfig.xml", "${pathToTomcat}/conf/ditacms/webconfig.xml")
            parseXml("${pathToTomcat}/conf/ditacms/webconfig.xml", "web")
            copyFile("${currentPath}/dita-cms/tomcat/log4j.properties", "${pathToTomcat}/conf/ditacms/log4j.properties")
            copyFile("${currentPath}/krb5.ini", "${pathToTomcat}/conf/krb5.ini")
            copyFile("${currentPath}/dita-cms/login.conf", "${pathToTomcat}/conf/login.conf")
            copyFile("${currentPath}/dita-cms/tomcat/xeditor.war", "${pathToTomcat}/webapps/xeditor.war")
            copyFile("${currentPath}/dita-cms/tomcat/ditacms.war", "${pathToTomcat}/webapps/ditacms.war")
        }
        //START
        osType.contains('linux') ? setupLinuxServices() : setupWindowsServices(asadmin, ixiaPath)
        copyFile("$currentPath/properties.txt", "$ixiaPath/properties.txt")
        println "Installation successful"
        System.exit(0)
    }
}