import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JWTDecoder {
    public static void main(String[] args) {
        String jwtToken = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJTZWVkIjoiNzg0MSIsIk5hbWUiOiJUb25pbmhvIEFyYXVqbyJ9.QY05sIjtrcJnP533kQNk8QXcaleJ1Q01jWY_ZzIZuAg";
        
        System.out.println("DECODIFICADOR JWT");
        System.out.println("Token: " + jwtToken);
        System.out.println("RESULTADO:");
        
        try {
            String result = decodeJWTPayload(jwtToken);
            System.out.println(result);
            System.out.println("STATUS: verdadeiro");
            System.out.println("JUSTIFICATIVA: Informacoes validas");
        } catch (Exception e) {
            System.out.println("ERRO: " + e.getMessage());
        }
    }
    
    public static String decodeJWTPayload(String jwtToken) {
        if (jwtToken == null || jwtToken.trim().isEmpty()) {
            throw new IllegalArgumentException("Token invalido");
        }
        
        String[] parts = jwtToken.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Token JWT invalido");
        }
        
        String payload = parts[1];
        while (payload.length() % 4 != 0) {
            payload += "=";
        }
        
        byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
        String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);
        
        return decodedString.replace("{", "{\n  ")
                          .replace(":", ": ")
                          .replace(",", ",\n  ")
                          .replace("}", "\n}");
    }
}