TEST PLAYER — DEPLOYMENT
========================
Server: 51.75.142.7

STEP 1 — Server setup (run once on the server as root)
-------------------------------------------------------
Upload setup.sh to the server and run it:

  scp setup.sh root@51.75.142.7:/tmp/
  ssh root@51.75.142.7 'bash /tmp/setup.sh'

SAVE THE ADMIN PASSWORD IT PRINTS.


STEP 2 — Deploy the app (run from YOUR machine)
-----------------------------------------------
From this folder (test-player-deploy):

  bash deploy.sh

That's it. The script uploads everything, runs migrations,
seeds the database, starts the service and checks health.


STEP 3 — Open it
-----------------
  Browser: http://51.75.142.7
  Login:   admin@catandwickets.com
  Pass:    (from Step 1 output)


MANAGING THE SERVICE
--------------------
  View logs:    ssh root@51.75.142.7 'journalctl -u test-player -f'
  Restart:      ssh root@51.75.142.7 'systemctl restart test-player'
  Status:       ssh root@51.75.142.7 'systemctl status test-player'
  Stop:         ssh root@51.75.142.7 'systemctl stop test-player'


TV DISPLAY SETUP
-----------------
1. Log in as admin
2. Go to Displays in the sidebar
3. Click "Create display" → select venue
4. Copy the URL
5. Open it on any browser connected to the pub TV
   (works full screen — no login required)


ADDING CONNECTORS
------------------
1. Go to Connectors in the sidebar
2. Click "Add connector"
3. Enter provider name, base URL, auth type
4. Click "Credentials" to add your API key/token
5. Click "Test" to verify the connection


RUN THE SELECTOR MANUALLY
--------------------------
Log in as admin → Scores → "Run The Selector" button
(also runs automatically every Sunday at 23:00)


TROUBLESHOOTING
----------------
  Nginx logs:  ssh root@51.75.142.7 'tail -f /var/log/nginx/test-player-error.log'
  DB connect:  ssh root@51.75.142.7 'grep DB_ /etc/test-player/.env'
  Env file:    /etc/test-player/.env
  App files:   /var/www/test-player/
