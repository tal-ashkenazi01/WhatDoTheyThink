### What do they think:
To run this locally, you must remove the following lines from routing.py:

import os
port = int(os.getenv('PORT'))

These two lines are used to deploy the app to heroku, and are not used for the application
