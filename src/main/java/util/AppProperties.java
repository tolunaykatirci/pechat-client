package util;


import lombok.*;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class AppProperties {

    private int port;
    private String userName;
    private String publicKeyPath;
    private String privateKeyPath;
    private String certificatePath;

    private String serverIp;
    private int serverPort;
}
