"""Quick health check. Run:  .venv/bin/python doctor.py
Shows exactly what the app can and cannot read on this Mac, without sending anything."""
import config
import mac

print("\n--- doctor ---")
t = mac.latest_text()
print("Latest text :", ("OK, from %s, %d min ago: %r" % (t["sender"], t["minutes_ago"], t["body"][:60])) if t
      else "NOT READABLE  -> give this app Full Disk Access")
e = mac.latest_email()
print("Latest email:", ("OK, from %s: %r" % (e["sender"], e["subject"][:60])) if e
      else "none  -> open Mail.app (and allow the Automation prompt)")
s = mac.screenshot()
print("Screenshot  :", ("OK, %d KB" % (len(s) // 1024)) if s
      else "NOT ALLOWED  -> give this app Screen Recording")
print("Gemini key  :", "set" if config.GEMINI_API_KEY else "MISSING")
print("MongoDB     :", "set" if config.MONGODB_URI else "MISSING")
print("Family phone:", config.FAMILY_PHONE or "MISSING")
print("Trusted cts :", ("%d configured" % (len(config.TRUSTED_CONTACTS) + (1 if config.FAMILY_PHONE else 0)))
      if (config.TRUSTED_CONTACTS or config.FAMILY_PHONE) else "none")
print("Verify phrase:", "set" if config.VERIFY_PHRASE else "optional, not set")
print("Scam memory :", "%d days" % config.SCAM_MEMORY_DAYS)
print("Permissions are in System Settings > Privacy & Security. Quit and reopen the")
print("terminal app after changing them.\n")
