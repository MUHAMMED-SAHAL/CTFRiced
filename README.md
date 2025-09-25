Ricing CTFd to the best of my abilities!

CTFd [Latest](https://github.com/CTFd/CTFd/releases/latest)

2025 Infra [`on the pot`]
- 3.7.7 [Tag](https://github.com/AbuCTF/CTFRiced/releases/tag/3.7.7) <- fully tested
  - multiple plugin support + custom ui
    - docker challenges
    - anti cheat
- 3.8.0 [`cooked`]
  - discord notifier
  - geoint support
  - fractal theme (without fractals lol)


#### **Instructions**

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
UPDATE pages SET content = '<div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; min-height: 100vh; text-align: center; padding: 20px; box-sizing: border-box; overflow: hidden; transform: translateY(-30px);"><img src="/themes/core/static/img/logo.png" alt="CTF Banner" style="max-width: 300px; width: 100%; margin-bottom: 25px;" /><div id="countdown" style="font-family: Courier; color: #64ffda; font-size: 1.5rem; margin-bottom: 35px;">Loading...</div><div style="display: flex; justify-content: center; align-items: center; gap: 20px; flex-wrap: wrap;"><a href="/challenges" style="background: #1e3a3a !important; color: #64ffda !important; padding: 14px 20px !important; text-decoration: none !important; border: 2px solid #64ffda !important; border-radius: 4px !important; font-weight: 600 !important; display: flex !important; justify-content: center !important; align-items: center !important; width: 140px !important; height: 20px !important; box-sizing: border-box !important; font-size: 13px !important; white-space: nowrap !important; transition: all 0.15s ease !important; letter-spacing: 1px !important; text-transform: uppercase !important; box-shadow: 0 2px 4px rgba(0,0,0,0.3) !important; font-family: -apple-system, BlinkMacSystemFont, ''Segoe UI'', Roboto, sans-serif !important;" onmouseover="this.style.background=''#2a4a4a''; this.style.boxShadow=''0 4px 8px rgba(0,0,0,0.4)''; this.style.transform=''translateY(-1px)''" onmouseout="this.style.background=''#1e3a3a''; this.style.boxShadow=''0 2px 4px rgba(0,0,0,0.3)''; this.style.transform=''translateY(0)''" onmousedown="this.style.transform=''translateY(1px) scale(0.98)''; this.style.boxShadow=''0 1px 2px rgba(0,0,0,0.4)''" onmouseup="this.style.transform=''translateY(-1px)''; this.style.boxShadow=''0 4px 8px rgba(0,0,0,0.4)''">ENTER ARENA</a><a href="/register" style="background: #3a1e1e !important; color: #ff6b6b !important; padding: 14px 20px !important; text-decoration: none !important; border: 2px solid #ff6b6b !important; border-radius: 4px !important; font-weight: 600 !important; display: flex !important; justify-content: center !important; align-items: center !important; width: 140px !important; height: 20px !important; box-sizing: border-box !important; font-size: 13px !important; white-space: nowrap !important; transition: all 0.15s ease !important; letter-spacing: 1px !important; text-transform: uppercase !important; box-shadow: 0 2px 4px rgba(0,0,0,0.3) !important; font-family: -apple-system, BlinkMacSystemFont, ''Segoe UI'', Roboto, sans-serif !important;" onmouseover="this.style.background=''#4a2a2a''; this.style.boxShadow=''0 4px 8px rgba(0,0,0,0.4)''; this.style.transform=''translateY(-1px)''" onmouseout="this.style.background=''#3a1e1e''; this.style.boxShadow=''0 2px 4px rgba(0,0,0,0.3)''; this.style.transform=''translateY(0)''" onmousedown="this.style.transform=''translateY(1px) scale(0.98)''; this.style.boxShadow=''0 1px 2px rgba(0,0,0,0.4)''" onmouseup="this.style.transform=''translateY(-1px)''; this.style.boxShadow=''0 4px 8px rgba(0,0,0,0.4)''">JOIN NOW</a></div></div><style>body { overflow: hidden !important; margin: 0 !important; padding: 0 !important; } html { overflow: hidden !important; }</style><script>document.addEventListener("DOMContentLoaded", function() { var countdownElement = document.getElementById("countdown"); var ctfStart = new Date("2025-10-11T09:00:00+05:30"); var ctfEnd = new Date("2025-12-12T21:00:00+05:30"); function updateCountdown() { var now = new Date(); if (now >= ctfEnd) { countdownElement.textContent = "ENDED"; return; } if (now >= ctfStart) { countdownElement.textContent = "LIVE"; return; } var distance = ctfStart - now; var days = Math.floor(distance / (1000 * 60 * 60 * 24)); var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)); var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60)); var seconds = Math.floor((distance % (1000 * 60)) / 1000); countdownElement.textContent = days + "D " + hours + "H " + minutes + "M " + seconds + "S"; } updateCountdown(); setInterval(updateCountdown, 1000); });</script>' WHERE id = 1;
```
- for database backups
```
docker exec <repo>-db-1 mysqldump -u root -p ctfd > backup.sql
```
quick fun fact: `mysqldump`
 is the utility that generates SQL queries from a running database.

- to restore DB
```
docker exec -i <repo>-db-1 mariadb -u root -p ctfd < backup.sql
```

#### Post Credits
H7CTF 2024 Infrastructure [writeup](https://abu.h7tex.com/docs/docs/dev/h7ctfinfra/)
