Work in progress


## Struct
- Token
    - Token string
    - Secret string

## Functions
### ReadToken(file string) (\*Token, \*Token, error)
Read consumer key, secret and access token, secret from file.

### GetRequestToken(consumer \*Token) (\*Token, error)
Get request token, secret and return them.

### GetAccessToken(consumer \*Token, access \*Token) error
Get access token, secret and stores them into access \*Token

### GetPinUrl(requtoken \*Token) string
Create a url to retrieve PIN code.

### SaveTokens(filename string, consumer \*Token, access \*Token)
Save consumer key, secret and access token, secret into a file.
