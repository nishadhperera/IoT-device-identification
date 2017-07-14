from phue import Bridge
from time import sleep

b = Bridge('192.168.1.168')

# If the app is not registered and the button is not pressed, press the button and call connect() (this only needs to be run a single time)
b.connect()

# Get the bridge state (This returns the full dictionary that you can explore)
b.get_api()

lights = b.lights

# Print light names
for l in lights:
    print(l.name)

b.set_light(2,'on', True)
b.set_light(2, 'bri', 2)
sleep(4)
b.set_light(2, 'bri', 200)
sleep(4)
b.set_light(2,'on', False)