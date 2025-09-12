Ricing CTFd to the best of my abilities!

CTFd [Latest](https://github.com/CTFd/CTFd/releases/latest)

2025 Infra [`on the pot`]
- 3.7.7 [Tag](https://github.com/AbuCTF/CTFRiced/releases/tag/3.7.7) <- fully tested
  - multiple plugin support + custom ui
    - docker challenges
    - anti cheat
- 3.8.8 [`cooking`]


### Instructions

```
git clone https://github.com/AbuCTF/CTFRiced.git
docker compose up --build
```
then paste `theme-header.css` and `theme-footer.js` in [localhost](https//localhost:8000/admin/config)

to take it one step further and customize landing page (optional)
```
docker exec -it ctfd-db-1 bash
mysql -u ctfd -p
```
password is `ctfd` (unless you explicitly changed it in the docker-compose.yml file)
```mysql
use ctfd;
UPDATE pages SET content = '<div class="row"><div class="col-md-6 offset-md-3"><img class="w-100 mx-auto d-block" style="max-width: 500px; padding: 50px; padding-top: 14vh;" src="/themes/core-beta/static/img/logo.png" alt="H7CTF Banner" /><h2 class="text-center" style="margin-top: 20px; font-weight: 700; letter-spacing: 2px;">H7CTF</h2><p class="text-center" style="font-size: 1.2rem; color: #888; margin-top: 10px;">Test your skills. Prove your worth. Only the relentless survive.</p><div class="text-center" style="margin-top: 20px;"><h4 id="countdown" style="font-weight: 600; color: #e74c3c;">Loading...</h4></div><br><div class="text-center"><a href="/challenges" class="btn btn-primary btn-lg mx-2">Enter Arena</a><a href="/register" class="btn btn-outline-secondary btn-lg mx-2">Join Now</a></div></div></div><script>const countdownElement=document.getElementById("countdown");const ctfStart=new Date("2025-10-11T09:00:00+05:30");const ctfEnd=new Date("2025-10-12T21:00:00+05:30");function updateCountdown(){const now=new Date();if(now>=ctfEnd){countdownElement.innerHTML="<span style=color:#95a5a6;>ENDED</span>";return;}if(now>=ctfStart&&now<ctfEnd){countdownElement.innerHTML="<span style=color:#2ecc71;>LIVE</span>";return;}const distance=ctfStart-now;const days=Math.floor(distance/(1000*60*60*24));const hours=Math.floor((distance%(1000*60*60*24))/(1000*60*60));const minutes=Math.floor((distance%(1000*60*60))/1000/60);const seconds=Math.floor((distance%(1000*60))/1000);countdownElement.textContent=`${days}d ${hours}h ${minutes}m ${seconds}s`;}updateCountdown();setInterval(updateCountdown,1000);</script>' WHERE route = 'index';
```

### Post Credits
H7CTF 2024 Infrastructure [writeup](https://abu.h7tex.com/docs/docs/dev/h7ctfinfra/)
