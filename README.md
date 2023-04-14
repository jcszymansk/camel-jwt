### camel-jwt: Example camel component

This is a camel component I wrote to use with my realworld.io 
backend camel [example](https://github.com/jacekszymanski/realworld-camel-springboot) application. 

This component only supports the required none and HS256 algorithms.

To build, run:

```
    mvn clean install
```

Although it's meant as an example, and thus very limited, I tried
my best to write it just like I would write a production quality
component. 

I tried to cover as much code as possible with unit tests, 
especially all the mistakes I made while coding.

Being a limited example, much functionality could be added,
such as:
* checking various predefined claims, such as audience, time, etc.
* other algorithms, esp. asymmetric ones
* respecting the "alg" header (but see https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
* multiple keys via key ids

But, within its limits, this component should be usable.

This component is written for camel 3.20. For the actual work it uses
the [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) library.
