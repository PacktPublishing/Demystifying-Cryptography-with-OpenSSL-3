# Demystifying Cryptography with OpenSSL 3.0

<a href="https://www.packtpub.com/product/demystifying-cryptography-with-openssl-3/9781800560345?utm_source=github&utm_medium=repository&utm_campaign=9781800560345"><img src="https://static.packt-cdn.com/products/9781800560345/cover/smaller" alt="About the Author" height="256px" align="right"></a>

This is the code repository for [Demystifying Cryptography with OpenSSL 3.0](https://www.packtpub.com/product/demystifying-cryptography-with-openssl-3/9781800560345?utm_source=github&utm_medium=repository&utm_campaign=9781800560345), published by Packt.

**Discover the best techniques to enhance your network security with OpenSSL 3.0**

## What is this book about?
Security and networking are essential features of software today. The modern internet is full of worms, Trojan horses, men-in-the-middle, and other threats. This is why maintaining security is more important than ever. 

This book covers the following exciting features:
* Understand how to use symmetric cryptography
* Get to grips with message digests, MAC, and HMAC
* Discover asymmetric cryptography and digital signatures
* Focus on how to apply and use X.509 certificates
* Dive into TLS and its proper usage
* Manage advanced and special usages of TLS
* Find out how to run a mini certificate authority for your organization

If you feel this book is for you, get your [copy](https://www.amazon.com/dp/1800560346) today!

<a href="https://www.packtpub.com/?utm_source=github&utm_medium=banner&utm_campaign=GitHubBanner"><img src="https://raw.githubusercontent.com/PacktPublishing/GitHub/master/GitHub.png" 
alt="https://www.packtpub.com/" border="5" /></a>

## Instructions and Navigations
All of the code is organized into folders. For example, Chapter02.

The code will look like the following:
```
if (pinned_server_cert)
    X509_free(pinned_server_cert);
if (pinned_server_cert_file)
    fclose(pinned_server_cert_file);
```

This Git repository contains code examples.
All code examples are written in C.

**How to build on Unix/Linux**

It is very easy to build the code examples on Linux or another Unix-compatible system with GNU Make, such as macOS or even Cygwin.

**Prerequisites**

1. Install essential build tools: C compiler, linker, GNU Make.
2. Build OpenSSL 3.0 and install it to /opt/openssl-3.0.0/ .

**Build code examples**

1. Enter a directory containing the code examples for a particular chapter, for example:
```
cd Chapter02
```

2. Build with GNU Make:
```
make
```

**Following is what you need for this book:**
This book is for software developers, system administrators, DevOps specialists, network security engineers, and analysts, or anyone who wants to keep their applications and infrastructure secure. Software developers will learn how to use the OpenSSL library to empower their software with cryptography and TLS. DevOps professionals and sysadmins will learn how to work with cryptographic keys and certificates on the command line, and how to set up a mini-CA for their organization. A basic understanding of security and networking is required.

With the following software and hardware list you can run all code files present in the book (Chapter 02).
### Software and Hardware List
| Chapter | Software required | OS required |
| -------- | ------------------------------------ | ----------------------------------- |
| 1-12 | OpenSSL 3.0 | Windows, Mac OS X, and Linux (Any) |

We also provide a PDF file that has color images of the screenshots/diagrams used in this book. [Click here to download it](https://packt.link/c0WEO).

### Related products
* Cryptography Algorithms [[Packt]](https://www.packtpub.com/product/cryptography-algorithms/9781789617139/?utm_source=github&utm_medium=repository&utm_campaign=9781789617139) [[Amazon]](https://www.amazon.com/dp/1789617138)

* Modern Cryptography for Cybersecurity Professionals [[Packt]](https://www.packtpub.com/product/modern-cryptography-for-cybersecurity-professionals/9781838644352/?utm_source=github&utm_medium=repository&utm_campaign=9781838644352) [[Amazon]](https://www.amazon.com/dp/1838644350)

## Get to Know the Author
**Alexei Khlebnikov**
has more than 20 years of professional experience in IT where he has worked in a host of different roles – software developer, system administrator, DevOps engineer, technical leader, architect, and project manager. During these years, Alexei has worked with many technologies – security, artificial intelligence, web development, embedded, mobile, and robotics. Among other companies, Alexei worked for Opera Software on the famous Opera internet browser. Alexei has always been interested in security. He was one of the maintainers of the security-related Opera browser modules, responsible for cryptography, SSL/TLS, and integration with OpenSSL. He was also a member of the security architect group, responsible for the security of the Opera browser. Now, Alexei lives in Oslo, Norway, and works as a senior consultant for bspoke AS. He is also the leader of the architect group at his current employer.
### Download a free PDF

 <i>If you have already purchased a print or Kindle version of this book, you can get a DRM-free PDF version at no cost.<br>Simply click on the link to claim your free PDF.</i>
<p align="center"> <a href="https://packt.link/free-ebook/9781800560345">https://packt.link/free-ebook/9781800560345 </a> </p>