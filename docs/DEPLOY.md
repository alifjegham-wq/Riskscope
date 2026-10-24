# Running riskscope for free (from a phone)

There are two free ways to run riskscope. Both work entirely from a phone browser:

| | **A. GitHub Codespaces** | **B. Render (free plan)** |
|---|---|---|
| Who can use it | Just you (private) | Anyone with the link (public) |
| Cost | Free: 120 core-hours/month on a personal GitHub account (≈ 60 h on the default 2-core machine) | Free web service |
| Card needed | No | Possibly, depending on Render's sign-up rules |
| Always on? | Starts when you open it, stops after 30 min idle | Sleeps after 15 min without visitors; next visit takes up to a minute |
| Sharing & monitoring | Yes (saved in the Codespace) | Off (the free disk is wiped on restart) |

Either way you can **install riskscope as an app** on your home screen (see the end).

---

## A. Run your own private copy with GitHub Codespaces

1. On your phone, open **https://github.com/alifjegham-wq/Riskscope** (signed in to GitHub).
2. Tap **Code** → **Codespaces** → **Create codespace on main**.
   (If the mobile page hides it, use the browser menu → "Desktop site".)
3. Wait a minute or two. The repo's `.devcontainer` installs everything and **starts riskscope by itself**.
4. A tab opens with riskscope. If it doesn't, open the **Ports** panel in the editor and tap the globe next
   to port **8000**. The address looks like `https://<name>-8000.app.github.dev`.
5. Bookmark that address or install it as an app. Next time, start the Codespace from
   https://github.com/codespaces and the app starts with it.

Good to know:
- The port is **private**: only your GitHub account can open it. To show someone a report, make port 8000
  public in the Ports panel (right-click / long-press → Port visibility → Public). Make it private again
  afterwards.
- The Codespace stops after 30 minutes of inactivity, which saves your free hours. Monitoring checks only
  run while it's on, so use Option B (paid) for real monitoring.
- Logs: in the Codespace terminal, run `tail -f /tmp/riskscope.log`.

---

## B. Put it online for everyone with Render's free plan

1. Open **https://render.com/deploy?repo=https://github.com/alifjegham-wq/Riskscope**
2. Sign in with GitHub and allow Render to access the `Riskscope` repository.
3. Tap **Apply** / **Deploy Blueprint**. No fields need filling in. The first build takes a few minutes.
4. When the service shows **Live**, its `https://riskscope-xxxx.onrender.com` address is your public site.

On the free plan riskscope runs with `RISKSCOPE_PERSISTENT_STORAGE=false`. Scanning websites and code works
fully. **Shareable links and monitoring are hidden**, because the free disk is wiped whenever the instance
restarts or wakes from sleep, and saved links would silently break.

### Upgrading later (paid)

To get shareable links and monitoring, edit `render.yaml`:
1. Set `plan: starter`.
2. Add the `disk:` block shown in its comments.
3. Set `RISKSCOPE_PERSISTENT_STORAGE` to `"true"`.

Then add these in Render under **Environment**:
| Variable | Example |
|---|---|
| `RISKSCOPE_SMTP_HOST` | `smtp-relay.brevo.com` |
| `RISKSCOPE_SMTP_PORT` | `587` |
| `RISKSCOPE_SMTP_USERNAME` / `RISKSCOPE_SMTP_PASSWORD` | from your provider |
| `RISKSCOPE_SMTP_FROM` | `riskscope <alerts@yourdomain.com>` |

Brevo, Resend, Postmark and Mailgun all have free email tiers. Monitoring appears once SMTP is set.

### Custom domain (optional)

In the service's **Settings → Custom Domains**, add e.g. `scan.yourdomain.com` and create the DNS record
Render shows. Then set `RISKSCOPE_PUBLIC_BASE_URL=https://scan.yourdomain.com`.

### Before you announce it

- **Rate limit:** `RISKSCOPE_SCANS_PER_HOUR` (default 20 per visitor IP per hour).
- **Logs:** the Render dashboard's **Logs** tab.
- **Network safety:** riskscope refuses private/internal addresses and re-checks every redirect.
- **Keep it to one instance:** the scheduler, SQLite and the rate limiter assume a single process.
- **Never change `RISKSCOPE_VERIFY_SECRET`:** it's generated once and signs ownership tokens.

---

## Other hosts we looked at (October 2026)

- **Google Cloud Run** and **Oracle Cloud Always Free:** generous free tiers but need a card and a more
  involved setup. Good later. riskscope's Docker image runs there unchanged.
- **Koyeb:** its free tier's availability to new users is unclear.
- **Hugging Face Spaces:** free, but outbound connections are limited to a few ports, which breaks
  riskscope's DNS and port checks.
- **Fly.io, Railway:** no ongoing free tier.

Free tiers change often, so check the provider's pricing page before relying on one.

---

## Install it as an app

riskscope is an installable web app (PWA), with no app store needed. Open your riskscope address, then:

- **iPhone / iPad (Safari):** tap **Share** → **Add to Home Screen**.
- **Android (Chrome):** tap **⋮** → **Install app** (or **Add to Home screen**).

It gets its own icon and opens full screen. Scans still run on the server, so it needs a connection.
Offline, it shows a friendly offline page.
