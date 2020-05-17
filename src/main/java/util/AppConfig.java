package util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class AppConfig {

    public static AppProperties appProperties;
    public static String projectPath;
    public static FileHandler logHandler;

    public static void getApplicationProperties() {
        try {
            // read properties file

//            File jarPath=new File(AppConfig.class.getProtectionDomain().getCodeSource().getLocation().getPath());
//            projectPath = jarPath.getParent();
//            String propertiesPath=projectPath + "/config.properties";
//            System.out.println("propertiesPath:"+propertiesPath);
//
//            File file = new File(propertiesPath);
//            if(!file.isFile()){
//                System.out.println("Unable to find config.properties");
//                System.exit(-1);
//            }
//            InputStream input = new FileInputStream(propertiesPath);


            InputStream input = AppConfig.class.getClassLoader().getResourceAsStream("config2.properties");
            if (input == null) {
                System.out.println("Unable to find config.properties");
                System.exit(-1);
            }

            Properties properties = new Properties();
            // load properties file from class path, inside static method
            properties.load(input);

            appProperties = new AppProperties();
            appProperties.setPort(Integer.parseInt(properties.getProperty("client.port")));
            appProperties.setUserName(properties.getProperty("client.username"));
            appProperties.setLogFilePath(properties.getProperty("client.logger.log_file.path"));
            appProperties.setPublicKeyPath(properties.getProperty("client.security.public_key.path"));
            appProperties.setPrivateKeyPath(properties.getProperty("client.security.private_key.path"));
            appProperties.setCertificatePath(properties.getProperty("client.security.certificate.path"));
            appProperties.setServerIp(properties.getProperty("client.security.server_ip"));
            appProperties.setServerPort(Integer.parseInt(properties.getProperty("client.security.server_port")));

            logHandler = new FileHandler(appProperties.getLogFilePath(), true);
            System.setProperty("java.util.logging.SimpleFormatter.format",
                    "%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS %4$s: %5$s%6$s%n");
            SimpleFormatter formatter = new SimpleFormatter();
            logHandler.setFormatter(formatter);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static Logger getLogger(String className){
        Logger log = Logger.getLogger(className);
        log.addHandler(logHandler);
        log.setUseParentHandlers(false);
        return log;
    }
}
