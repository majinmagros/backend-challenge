import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JWTDecoder {
    
    public static void main(String[] args) {
        if (args.length > 0) {
            processToken(args[0]);
        } else {
            runAllTestCases();
        }
    }
    
    public static void runAllTestCases() {
        System.out.println("=== BACKEND CHALLENGE - TODOS OS CASOS ===");
        
        // Caso 1 (valido)
        System.out.println("\n--- Caso 1: Token Valido ---");
        processToken("eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJTZWVkIjoiNzg0MSIsIk5hbWUiOiJUb25pbmhvIEFyYXVqbyJ9.QY05sIjtrcJnP533kQNk8QXcaleJ1Q01jWY_ZzIZuAg");
        
        // Caso 2 (invalido - malformado)
        System.out.println("\n--- Caso 2: Token Invalido ---");
        processToken("eyJhbGciOiJzI1NiJ9.dfsdfsfryJSr2xrIjoiQWRtaW4iLCJTZrkIjoiNzg0MSIsIk5hbrUiOiJUb25pbmhvIEFyYXVqbyJ9.QY05fsdfsIjtrcJnP533kQNk8QXcaleJ1Q01jWY_ZzIZuAg");
        
        // Caso 3 (invalido - nome com numero)
        System.out.println("\n--- Caso 3: Token Invalido (Nome com numero) ---");
        processToken("eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiRXh0ZXJuYWwiLCJTZWVkIjoiODgwMzciLCJOYW1lIjoiTTRyaWEgT2xpdmlhIn0.6YD73XWZYQSSMDf6H0i3-kylz1-TY_Yt6h1cV2Ku-Qs");
    }
    
    public static void processToken(String jwtToken) {
        System.out.println("Token: " + jwtToken);
        
        try {
            JWTResult result = decodeAndValidateJWT(jwtToken);
            System.out.println("Resultado:");
            if (result.hasValidPayload()) {
                System.out.println(result.getFormattedPayload());
            }
            System.out.println("STATUS: " + result.getStatus());
            System.out.println("JUSTIFICATIVA: " + result.getJustification());
            
        } catch (Exception e) {
            System.out.println("Resultado:");
            System.out.println("STATUS: falso");
            System.out.println("JUSTIFICATIVA: JWT invalido");
        }
    }
    
    public static JWTResult decodeAndValidateJWT(String jwtToken) {
        if (jwtToken == null || jwtToken.trim().isEmpty()) {
            return new JWTResult(null, false, "Token nao pode ser vazio");
        }
        
        String[] parts = jwtToken.split("\\.");
        if (parts.length != 3) {
            return new JWTResult(null, false, "JWT invalido");
        }
        
        try {
            String header = decodeBase64URL(parts[0]);
            String payload = decodeBase64URL(parts[1]);
            
            if (!isValidJSON(payload)) {
                return new JWTResult(null, false, "JWT invalido");
            }
            
            // Validação específica do Caso 3: Name não pode conter números
            String nameValue = extractNameFromPayload(payload);
            if (nameValue != null && containsDigit(nameValue)) {
                return new JWTResult(null, false, "Abrindo o JWT, a Claim Name possui caracter de numeros");
            }
            
            return new JWTResult(payload, true, "As informacoes contidas no JWT atendem a descricao");
            
        } catch (Exception e) {
            return new JWTResult(null, false, "JWT invalido");
        }
    }
    
    private static String decodeBase64URL(String encoded) {
        String padded = encoded;
        while (padded.length() % 4 != 0) {
            padded += "=";
        }
        byte[] decodedBytes = Base64.getUrlDecoder().decode(padded);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }
    
    private static boolean isValidJSON(String jsonString) {
        return jsonString != null && 
               jsonString.trim().startsWith("{") && 
               jsonString.trim().endsWith("}");
    }
    
    private static String extractNameFromPayload(String payload) {
        // Extrai o valor do campo "Name" usando regex
        Pattern pattern = Pattern.compile("\"Name\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(payload);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    private static boolean containsDigit(String str) {
        // Verifica se a string contém algum dígito
        for (char c : str.toCharArray()) {
            if (Character.isDigit(c)) {
                return true;
            }
        }
        return false;
    }
    
    static class JWTResult {
        private String payload;
        private boolean valid;
        private String justification;
        
        public JWTResult(String payload, boolean valid, String justification) {
            this.payload = payload;
            this.valid = valid;
            this.justification = justification;
        }
        
        public boolean hasValidPayload() {
            return payload != null && valid;
        }
        
        public String getFormattedPayload() {
            if (payload == null) return null;
            return payload.replace("{", "{\n  ")
                         .replace(":", ": ")
                         .replace(",", ",\n  ")
                         .replace("}", "\n}");
        }
        
        public String getStatus() {
            return valid ? "verdadeiro" : "falso";
        }
        
        public String getJustification() {
            return justification;
        }
    }
}