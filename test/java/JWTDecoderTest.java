import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class JWTDecoderTest {

    @Test
    public void testCaso1_TokenValido() {
        // Arrange
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJTZWVkIjoiNzg0MSIsIk5hbWUiOiJUb25pbmhvIEFyYXVqbyJ9.QY05sIjtrcJnP533kQNk8QXcaleJ1Q01jWY_ZzIZuAg";
        
        // Act
        JWTDecoder.JWTResult result = JWTDecoder.decodeAndValidateJWT(token);
        
        // Assert
        assertTrue(result.isValid());
        assertEquals("verdadeiro", result.getStatus());
        assertEquals("As informacoes contidas no JWT atendem a descricao", result.getJustification());
        assertNotNull(result.getPayload());
        assertTrue(result.getFormattedPayload().contains("Toninho Araujo"));
    }

    @Test
    public void testCaso2_TokenInvalidoMalformado() {
        // Arrange
        String token = "eyJhbGciOiJzI1NiJ9.dfsdfsfryJSr2xrIjoiQWRtaW4iLCJTZrkIjoiNzg0MSIsIk5hbrUiOiJUb25pbmhvIEFyYXVqbyJ9.QY05fsdfsIjtrcJnP533kQNk8QXcaleJ1Q01jWY_ZzIZuAg";
        
        // Act
        JWTDecoder.JWTResult result = JWTDecoder.decodeAndValidateJWT(token);
        
        // Assert
        assertFalse(result.isValid());
        assertEquals("falso", result.getStatus());
        assertEquals("JWT invalido", result.getJustification());
        assertNull(result.getPayload());
    }

    @Test
    public void testCaso3_TokenComNomeInvalido() {
        // Arrange
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiRXh0ZXJuYWwiLCJTZWVkIjoiODgwMzciLCJOYW1lIjoiTTRyaWEgT2xpdmlhIn0.6YD73XWZYQSSMDf6H0i3-kylz1-TY_Yt6h1cV2Ku-Qs";
        
        // Act
        JWTDecoder.JWTResult result = JWTDecoder.decodeAndValidateJWT(token);
        
        // Assert
        assertFalse(result.isValid());
        assertEquals("falso", result.getStatus());
        assertEquals("Abrindo o JWT, a Claim Name possui caracter de numeros", result.getJustification());
        assertNotNull(result.getPayload()); // Deve mostrar o JSON mesmo sendo inválido
        assertTrue(result.getFormattedPayload().contains("M4ria Olivia"));
    }

    @Test
    public void testCaso4_TokenComMaisDe3Claims() {
        // Arrange
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiTWVtYmVyIiwiT3JnIjoiQlIiLCJTZWVkIjoiMTQ2MjciLCJOYW1lIjoiVmFsZGlyIEFyYW5oYSJ9.cmrXV_Flm5mfdpfNUVopY_I2zeJUy4EZ4i3Fea98zvY";
        
        // Act
        JWTDecoder.JWTResult result = JWTDecoder.decodeAndValidateJWT(token);
        
        // Assert
        assertFalse(result.isValid());
        assertEquals("falso", result.getStatus());
        assertEquals("Abrindo o JWT, foi encontrado mais de 3 claims", result.getJustification());
        assertNotNull(result.getPayload());
        assertTrue(result.getFormattedPayload().contains("Org"));
    }

    @Test
    public void testTokenNulo() {
        // Arrange
        String token = null;
        
        // Act
        JWTDecoder.JWTResult result = JWTDecoder.decodeAndValidateJWT(token);
        
        // Assert
        assertFalse(result.isValid());
        assertEquals("falso", result.getStatus());
        assertEquals("Token nao pode ser vazio", result.getJustification());
    }

    @Test
    public void testTokenVazio() {
        // Arrange
        String token = "";
        
        // Act
        JWTDecoder.JWTResult result = JWTDecoder.decodeAndValidateJWT(token);
        
        // Assert
        assertFalse(result.isValid());
        assertEquals("falso", result.getStatus());
        assertEquals("Token nao pode ser vazio", result.getJustification());
    }

    @Test
    public void testTokenComApenasDuasPartes() {
        // Arrange
        String token = "parte1.parte2";
        
        // Act
        JWTDecoder.JWTResult result = JWTDecoder.decodeAndValidateJWT(token);
        
        // Assert
        assertFalse(result.isValid());
        assertEquals("falso", result.getStatus());
        assertEquals("JWT invalido", result.getJustification());
    }
}