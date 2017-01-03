# asymmetric-passwords
Copyright (c) 2016, 2017 Mehdi Sotoodeh, Kryptologik Inc.

Passwords are the most common form of authentication used to control access to information and services. Passwords are widely used because they are simple, inexpensive, and convenient mechanisms to use and implement.

At the same time, passwords are also recognized as being an extremely poor form of protection. It is estimated that more than 80 percent of the reported security incidents are password related. 

AsymmetricPasswords addresses some of the password related issues by utilizing asymmetric cryptography. A dedicated library derives a private key from id/password/domain and shares the associated public key with sever during registration phase. Client library generates a signed timestamped token as the evidence of its authenticity where this token is a url-safe ANSI string. On the server side, passwords are replaced with associated public keys. 

Format of the generated tokens: tag.timestamp.payload.signature
    
Payload part of the token may include custom information (using URL-safe ANSI characters).
    tag.timestamp.payload.custom.signature
    
Signature field is the last item and is generated using the private key and presented as url-safe base-64 string.

User login:
-----------
```
 USER               BROWSER                            SERVER
 ----               -------                            ------
  |                   |                                  |
  | --id,password---> |                                  |
  |        Kpriv = KDF(id,password,domain)               | 
  |         token = li.timestamp.duration                |
  |         signature = Kpriv.SIGN(token)                |
  |                   | ---id,token.signature----------> |
  |                   |                           Kpub = DB[id].key
  |                   |                     Kpub.VERIFY(token.signature)
  |                   |                        Verify token.timestamp
  |                   |                                  |
  |                   |                        Verify token.duration
  |                   |                                  |
  |                   |                             token expires
  |                   |                                  |

Where:
    KDF = Key Derivation Function
    ECC = Elliptic Curve Cryptosystem
    timestamp = seconds since 1/1/1970 UTC
    duration = number of seconds token is valid
```

        
With this approach:

    1.	Passwords stay private. 
        a.	Do not need to share passwords with anyone. Public keys will be given instead.
        b.	Passwords do not cross the line.
        c.	Protection against eavesdropping on network connections.
    2.	Promote enforcement of time-based access control.
        a.	Protection against replay attacks
        b.	Protects against token-reuse (One-time tokens).
    3.	Server side security breaches do not compromise user accounts.
        a.	Leaked user public keys do not compromise account access information.
        b.	Protection against insider threats.
        c.	Public keys can be stored in clear.
        d.	No need for secure connection during login process.
    4.	Passwords can be shared for multiple accounts.
        a.	KDF is client-only operation and may use domain-specific info for differentiation.
        b.	Reducing number of passwords to memorize. 
    5.	Support for random challenge/response authentication.
    6.	Password splitting option:
        a.	Part 1: Memorize this part of password.
        b.	Part 2: Long and complex password part. This part is going to be stored on specific machines individually.
        c.	Part 2 can be encrypted using part 1 as the key.
        d.	Ability to enforce logins from pre-determined computers.
        e.	A form of multi-factor authentication.
    7.	Ease of deployment. 
        a.	Passwords (or password hashes) can easily be converted to public keys.
        b.	No need to change user interface.
        c.	Push via login portals.
    8.	Extendable and flexible URL-safe token design.


Register a new user:
--------------------
```
 USER               BROWSER                            SERVER
  |                   |                                  |
  | --id,password,    |                                  |
  |   reset_info----> |                                  |
  |        Kpriv = KDF(id,password,domain)               | 
  |        Kpub = ECC.CalcPublicKey(Kpriv)               | 
  |    token = nu.timestamp.algo.Kpub.reset_info         |
  |         signature = Kpriv.SIGN(token)                |
  |                   | ---id,token.signature----------> |
  |                   |                    DB[id]={algo,Kpub,reset_info}
  |                   |                                  |

Where:
    algo = Identifier for the ECC algorithm/curve
    reset_info = information used for password reset
```


Change password:
----------------
```
 USER                    BROWSER                     SERVER
  |                         |                           |
  | --id,old_password,      |                           |
  |   new_password--------> |                           |
  |      new_Kpriv = KDF(id,new_password,domain)        | 
  |             new_Kpub = ECC(new_Kpriv)               | 
  |      old_Kpriv = KDF(id,old_password,domain)        | 
  |           token = cp.timestamp.new_Kpub             |
  |         signature = old_Kpriv.SIGN(token)           |
  |                         | ---token.signature------> |
  |                         |                    old_Kpub = DB[id]                   
  |                         |            old_Kpub.VERIFY(token.signature)
  |                         |            Verify token timestamp and duration
  |                         |           Replace user's old_Kpub with new_Kpub
  |                         |                On failure: Access Denied
  |                         |                           |
```

Challenged authentication:
--------------------------
```
 USER               BROWSER                             SERVER
  |                    |                                  |
  |                    |                        Generate random nonce 
  |                    |                   challenge = Kpub.ENCRYPT(nonce) 
  |                    | <-----------------challenge ---- | 
  |      nonce = Kpriv.DECRYPT(challenge)                 |
  |         token = cr.timestamp.nonce                    |
  |        signature = Kpriv.SIGN(token)                  |
  |                    | ---token.signature-------------> |
  |                    |                     Kpub.VERIFY(token.signature)
  |                    |                     Verify token.nonce == nonce
  |                    |                                  |
```

C++ and Javascript implementations of this project are provided here which uses ED25519 and PBKDF2-HMAC-SHA512 for KDF. The C++ ECC library is a clone of https://github.com/msotoodeh/curve25519 and Javascript implementation is based on https://github.com/dchest/tweetnacl-js library. 
     
