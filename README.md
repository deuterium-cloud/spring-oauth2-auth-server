## Spring boot Authorization Server v0.2.2

---

<br>
Demo for using Spring boot Authorization Server

The Spring Authorization Server require three main Dependencies:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
    <version>0.2.2</version>
</dependency>
```

<br>

The AuthorizationServerConfiguration class should contain:

```java
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
         OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
         
         // Enable CORS on Authentication Server endpoints
         http.cors(c -> {
            CorsConfigurationSource source = request -> {
               CorsConfiguration config = new CorsConfiguration();
               config.setAllowedOrigins(List.of("*"));
               config.setAllowedMethods(List.of("GET", "POST"));
               return config;
            };
            c.configurationSource(source);
         });
         
         return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        // Public client with no client_secret
        RegisteredClient publicClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("public-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://oidcdebugger.com/debug")
                .scope(OidcScopes.OPENID)
                .build();

        // Confidential client
        RegisteredClient confidentialClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("confidential-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD) // not implemented
                .redirectUri("https://oidcdebugger.com/debug")
                .scope(OidcScopes.OPENID)
                .scope("write")
                .scope("read")
                .clientSettings(ClientSettings.builder() // Ask User for scopes Consent 
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(publicClient, confidentialClient);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://localhost:8082") // The Auth Server's address
                .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> context.getClaims().claim("dev", "deuterium");
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = getKeyPair();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

   private RSAKey getKeyPair() {
      KeyPair keyPair = generateKeyPair();
      RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
      RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

      return new RSAKey.Builder(publicKey)
              .privateKey(privateKey)
              .keyID(UUID.randomUUID().toString())
              .build();
   }

   private KeyPair generateKeyPair() {
      KeyPair keyPair;
      try {
         KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
         keyPairGenerator.initialize(2048);
         keyPair = keyPairGenerator.generateKeyPair();
      } catch (Exception ex) {
         throw new IllegalStateException(ex);
      }
      return keyPair;
   }
}
```

<br>

**Beans:**

1. **authServerSecurityFilterChain** - add basic security configuration and remove security from standard OAuth2 endpoints.
2. **registeredClientRepository** - bean responsible for Client registration
3. **providerSettings** - bean responsible for Auth Server endpoints configuration, defaults are:
    * /oauth2/authorize - Authorization endpoint
    * /oauth2/token - Token endpoint
    * /oauth2/revoke - Token revocation
    * /oauth2/introspect  - Token introspection
    * /oauth2/jwks - JWK Set endpoint
4. **jwtCustomizer** - JWT customization - adding new claims or fields in header 
5. **jwkSource** - bean responsible for providing JWKs (getKeyPair() method is implemented by developer)

<br>

**The User settings** are defined in SecurityConfiguration class and this is the most basic example with in memory Users:

```java
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

   @Bean
   PasswordEncoder passwordEncoder() {
      return PasswordEncoderFactories.createDelegatingPasswordEncoder();
   }

    @Bean
    UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("{noop}pass")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
```

<br>

--- 

### OAuth Grant Types implemented in Spring boot Authorization Server v0.2.2
* Authorization code
* PKCE
* Client credentials
* Refresh token
<br>
---

### Authorization Code Grant Type
The Authorization Code grant type is used by confidential and public clients to exchange an authorization code for an 
access token. After the user returns to the client via the redirect URL, the application will get the authorization 
code from the URL and use it to request an access token. It is recommended that all clients use the PKCE extension with 
this flow as well to provide better security.

#### Authorization Code Flow
The Authorization Code grant type is used by web and mobile apps. It differs from most of the other grant types by 
first requiring the app launch a browser to begin the flow. At a high level, the flow has the following steps:
* The application opens a browser to send the user to the OAuth server
* The user sees the authorization prompt and approves the app’s request
* The user is redirected back to the application with an authorization code in the query string
* The application exchanges the authorization code for an access token

To begin of the authorization flow, the application constructs a URL with parameters:
```
http://localhost:8082/oauth2/authorize?
response_type=code
&client_id=confidential-client
&scope=read+openid
&redirect_uri=https%3A%2F%2Foidcdebugger.com%2Fdebug
&state=123456
```
The meaning of the parameters:

* response_type=code - always the same
* client_id - registered client name
* redirect_uri - for testing purposes: oidcdebugger.com/debug
* scope=read+openid - should be separated with space (%20) or with + (but not url encoded %2B)
* state=123456 - optional parameter

The Authorization server will respond with GET request to given redirect URL with two query parameters:
```
https://oidcdebugger.com/debug?
code=DO4waqAMyAAFYSI5xK...qyFgNMIlmDVRLMH_AmTOEOElbEPqvg
&state=123456
```
The meaning of the parameters:
* code - the authorization code generated by the authorization server, short-lived
* state - the same value sent in request. Used to prevent CSRF attacks

The second step is to obtain token by sending POST request to server with url encoded parameters.
If the Client Authentication method was set as:
```
.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
```
The request must contain basic authorization header:

```shell
curl --location --request POST 'localhost:8082/oauth2/token' \
--header 'Authorization: Basic Y29uZmlkZW50aWFsLWNsaWVudDpzZWNyZXQ=' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'redirect_uri=https://oidcdebugger.com/debug' \
--data-urlencode 'code=DO4waqAMyAAFYSI5xK...qyFgNMIlmDVRLMH_AmTOEOElbEPqvg'
```
Or, if set as:
```
.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
```
The request must contain client_id and client_secret as encoded params:
```shell
curl --location --request POST 'localhost:8082/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'redirect_uri=https://oidcdebugger.com/debug' \
--data-urlencode 'code=DO4waqAMyAAFYSI5xK...qyFgNMIlmDVRLMH_AmTOEOElbEPqvg' \
--data-urlencode 'client_id=confidential-client' \
--data-urlencode 'client_secret=secret'
```

* grant_type=authorization_code - always the same
* code - from previous response
* redirect_uri - same as in previous request

The Authorization server will respond with json similar to this one:

```json
{
    "access_token": "eyJraWQiOiJlY2E1NDBi...ZS02YTI4LTQyNiHcjmBFZcQ",
    "refresh_token": "YVogQrXp3beCC_h4xu...3K32ZiOrcKtWNC5SIgK785",
    "scope": "read openid",
    "id_token": "eyJraWQiOi8wbvlqTmOy...WdLYMd2Kt54lCeoAva6DfB20A",
    "token_type": "Bearer",
    "expires_in": 299
}
```

<br>

**Notes about OpenID Connect (scope=openid).** The first request can contain nonce as parameter. That is a custom
String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
The value is passed through unmodified from the Authentication Request to the ID Token.
If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce
parameter sent in the Authentication Request. If present in the Authentication Request,
Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent
in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce values used.
The nonce value is a case sensitive string.

---

### PKCE Grant Type

PKCE (Proof Key for Code Exchange) is an extension to the Authorization Code flow to prevent CSRF 
and authorization code injection attacks. PKCE is not a replacement for a client secret, and PKCE is recommended even 
if a client is using a client secret. PKCE was originally designed to protect the authorization code flow in mobile apps, 
and was later recommended to be used by single-page apps as well.
<br>

To use PKCE Grant type, the Client must have authorization type set:
```
.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
```

#### PKCE Code Flow

The client first creates a “code verifier“, cryptographically random string, 
between 43 and 128 characters long. Once the app has generated the code verifier, it uses that to derive the code challenge. 
For devices that can perform a SHA256 hash, the code challenge is a Base64-URL-encoded string of the SHA256 hash of 
the code verifier. Clients that do not have the ability to perform a SHA256 hash are permitted to use the plain 
code verifier string as the challenge
<br>

Generate the code verifier and the code challenge:

```java
SecureRandom random = new SecureRandom();

byte[] code = new byte[64];
    
random.nextBytes(code);

String code_verifier = Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(code);

MessageDigest md = MessageDigest.getInstance("SHA-256");

byte[] digest = md.digest(code_verifier.getBytes());
    
String code_challenge = Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(digest);
    
```
For example:
```java
String code_verifier = "cmiP3RmbWi0s5qxLLElPERqgLP1xW8UrqmH2nMhgz8r0N5sIjyY-tLQqUwL3oUaK3PYAZcznYnw4vxP0-B2dZA";
String code_challenge = "SQecwXKpMHTWddAKB9DflvTEVMHI4Kh66I0p0W2ICUY";
```
<br>

To begin of the PKCE authorization flow, the application constructs a URL with parameters:
```
http://localhost:8082/oauth2/authorize?
response_type=code
&client_id=public-client
&redirect_uri=https%3A%2F%2Foidcdebugger.com%2Fdebug
&scope=openid
&state=123456
&code_challenge=SQecwXKpMHTWddAKB9DflvTEVMHI4Kh66I0p0W2ICUY
&code_challenge_method=S256
```
The meaning of the parameters:

* response_type=code - always the same
* client_id - registered client name
* redirect_uri - for testing purpose: oidcdebugger.com/debug
* scope=openid 
* state=123456 - optional parameter
* code_challenge - constructed challenge 
* code_challenge_method=S256 - either plain or S256, depending on whether the challenge is the plain verifier string or the SHA256 hash of the string
  
The Authorization server will respond with GET request to given redirect URL with two query parameters:
```
https://oidcdebugger.com/debug?
code=DO4waqAMyAAFYSI5xK...qyFgNMIlmDVRLMH_AmTOEOElbEPqvg
&state=123456
```
The second step is to obtain token by sending POST request to server with url encoded parameters.
If the Client is Public Client and the Authentication method was set as:

```
.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
```
The request doesn't contain client secret in any form (authorization header or client_id and client_secret as encoded params)

```shell
curl --location --request POST 'localhost:8082/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'code=DO4waqAMyAAFYSI5xK...qyFgNMIlmDVRLMH_AmTOEOElbEPqvg' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'client_id=public-client' \
--data-urlencode 'code_verifier=cmiP3RmbWi0s5qxLLElPERqgLP1xW8UrqmH2nMhgz8r0N5sIjyY-tLQqUwL3oUaK3PYAZcznYnw4vxP0-B2dZA' \
--data-urlencode 'redirect_uri=https://oidcdebugger.com/debug'
```

If the Client is Confidential Client and the Authentication method was set as:

```
.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
```
or any other authentication method, the request **MUST** contain client id and client secret. For example:
```shell
curl --location --request POST 'localhost:8082/oauth2/token' \
--header 'Authorization: Basic Y29uZmlkZW50aWFsLWNsaWVudDpzZWNyZXQ=' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'code=DO4waqAMyAAFYSI5xK...qyFgNMIlmDVRLMH_AmTOEOElbEPqvg' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'client_id=public-client' \
--data-urlencode 'code_verifier=cmiP3RmbWi0s5qxLLElPERqgLP1xW8UrqmH2nMhgz8r0N5sIjyY-tLQqUwL3oUaK3PYAZcznYnw4vxP0-B2dZA' \
--data-urlencode 'redirect_uri=https://oidcdebugger.com/debug'
```

Similar as in the Authorization Code Grant Type, 
the Authorization server will respond with json.

--- 

### Client Credentials Grant Type

The Client Credentials grant type is used by clients to obtain an access token outside of the context of a user. 
This is typically used by clients to access resources about themselves rather than to access a user's resources.
The client needs to authenticate themselves for this request.

```shell
curl --location --request POST 'localhost:8082/oauth2/token' \
--header 'Authorization: Basic Y29uZmlkZW50aWFsLWNsaWVudDpzZWNyZXQ=' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=client_credentials' \
--data-urlencode 'scope=read'
```
The response json did not contain refresh_token.

---

### Refresh Token Grant Type

The Refresh Token grant type is used by clients to exchange a refresh token for an access token when the access token has expired. 
This allows clients to continue to have a valid access token without further interaction with the user.
The client needs to authenticate themselves for this request.
```shell
curl --location --request POST 'localhost:8082/oauth2/token' \
--header 'Authorization: Basic Y29uZmlkZW50aWFsLWNsaWVudDpzZWNyZXQ=' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=ndlXewLKTiPbcMgv...Amkot2PRTNcVRNIC8p7jB'
```
---

<br>

### Implicit and Password Grant Type are deprecated.

<br>

---

More resources: <br>
[Spring boot github: spring-authorization-server](https://github.com/spring-projects/spring-authorization-server/tree/main/samples) <br>
[Baeldung: Spring Security OAuth Authorization Server](https://www.baeldung.com/spring-security-oauth-auth-server) <br>
[The OAuth 2.0 docs](https://datatracker.ietf.org/doc/html/rfc6749) <br>
[Okta: OAuth Grant Types](https://oauth.net/2/grant-types/) <br>
