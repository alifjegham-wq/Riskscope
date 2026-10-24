# Deploying riskscope (works from a phone)

riskscope ships with a Render blueprint (`render.yaml`), so a public deployment is a few taps in a
browser. No terminal is needed.

## What you need

- The GitHub account that owns this repository.
- A Render account. Sign up at https://render.com with "Sign in with GitHub".
- A payment method on Render. The blueprint uses the **Starter** instance type plus a 1 GB disk, so
  shared reports and monitors survive restarts. Check https://render.com/pricing for the current price.
  To try it for free first, see "Free trial" below.
- *(Optional, for monitoring emails)* An SMTP provider. Many have free tiers, e.g. Brevo, Resend,
  Postmark or Mailgun. You need its host, username, password and a sender address on a domain you've
  verified with it.

## Deploy

1. Open this link on your phone:
   **https://render.com/deploy?repo=https://github.com/alifjegham-wq/riskscope**
2. Sign in with GitHub and allow Render to access the `riskscope` repository.
3. Render shows the blueprint: one web service called `riskscope` with a disk. Fill in the prompted values:
   - `RISKSCOPE_PUBLIC_BASE_URL`: **leave empty**. riskscope then uses `https://<name>.onrender.com`
     automatically. Fill it in only once you add a custom domain.
   - `RISKSCOPE_SMTP_*`: leave empty for now if you don't have an email provider yet (see below).
4. Tap **Apply** / **Deploy Blueprint**. The first build takes a few minutes.
5. When the service shows **Live**, open its `https://riskscope-xxxx.onrender.com` URL and run a scan.

`RISKSCOPE_VERIFY_SECRET` is generated for you. **Never change it**: it signs domain-verification tokens
and every monitor's manage/unsubscribe link.

## Turn on monitoring emails

Until an SMTP host is set, the "Keep watching your site" sign-up is hidden: confirmation emails would
have nowhere to go. One-off scans and shareable reports work either way.

1. In the Render dashboard, open the `riskscope` service and go to **Environment**.
2. Set:
   | Variable | Example |
   |---|---|
   | `RISKSCOPE_SMTP_HOST` | `smtp-relay.brevo.com` |
   | `RISKSCOPE_SMTP_PORT` | `587` |
   | `RISKSCOPE_SMTP_USERNAME` | from your provider |
   | `RISKSCOPE_SMTP_PASSWORD` | from your provider |
   | `RISKSCOPE_SMTP_FROM` | `riskscope <alerts@yourdomain.com>` |
3. Save. Render redeploys, and monitoring appears on the home page and under every website report.

To check it works, monitor a domain you own: you should receive the confirmation email within a minute.

## Custom domain (optional)

In the service's **Settings → Custom Domains**, add e.g. `scan.yourdomain.com` and create the DNS record
Render shows. Then set `RISKSCOPE_PUBLIC_BASE_URL=https://scan.yourdomain.com` so share links and emails
use it.

## Free trial

In `render.yaml`, change `plan: starter` to `plan: free` and delete the `disk:` block before deploying,
or pick "Free" when Render asks. Scanning works. Free instances sleep when idle (the first visit after a
break takes a while) and lose their files on every restart, so shared links and monitors don't last.
Don't enable monitoring on the free plan.

## Updating

`autoDeploy` is on: every merge to `main` redeploys automatically. The SQLite database on the disk is
upgraded in place on startup.

## Before you announce it

- **Rate limit:** `RISKSCOPE_SCANS_PER_HOUR` (default 20 per visitor IP per hour). Lower it if you see
  abuse.
- **Logs:** the Render dashboard's **Logs** tab shows every request and any errors.
- **Network safety:** riskscope refuses to scan private or internal addresses and re-checks every
  redirect. On Render you can't add an outbound firewall, so don't run other private services in the same
  Render account and region that would be reachable from it.
- **One instance:** keep the instance count at 1. The scheduler, SQLite and the rate limiter assume a
  single process.
