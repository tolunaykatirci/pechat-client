package util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class AppConfig {

    public static AppProperties appProperties;
    public static String projectPath;

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
            appProperties.setPublicKeyPath(properties.getProperty("client.security.public_key.path"));
            appProperties.setPrivateKeyPath(properties.getProperty("client.security.private_key.path"));
            appProperties.setCertificatePath(properties.getProperty("client.security.certificate.path"));
            appProperties.setServerIp(properties.getProperty("client.security.server_ip"));
            appProperties.setServerPort(Integer.parseInt(properties.getProperty("client.security.server_port")));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
