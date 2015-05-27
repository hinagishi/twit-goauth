Work in progress


## Struct
- Token
    - Token string
    - Secret string

## Functions
` ReadToken(file string) (*Token, *Token, string, error)`  
Read consumer key, consumer secret, access token, access secret and screen name from file.

` GetAccessToken(consumer *Token, token *Token, config map[string]string) (*Token, string, error)`  
Get access token, access secret and screen name. Then, it stores them into access *Token and name

` GetRequestToken(consumer *Token, config map[string]string) (*Token, error)`  
Get request token, secret and return them.

` GetPinUrl(requtoken *Token) string`  
Create a url to retrieve PIN code.

` SaveTokens(filename string, consumer *Token, access *Token, name string)`  
Save consumer key, secret and access token, secret into a file.

` CreateOauthTemplate(consumer *Token) map[string]string`  
create a map which includes the oauth verifier information.
