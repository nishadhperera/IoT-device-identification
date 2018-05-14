# This application supports operation of a Philips Hue smart bulb using Python

from phue import Bridge
from time import sleep

IP = "192.168.1.168"
b = Bridge(IP)


def connect(b):
    # If the app is not registered and the button is not pressed, press the button and call connect()
    # (this only needs to be run a single time)
    b.connect()
    b.get_api()     # Get the bridge state (This returns the full dictionary that you can explore)


def list_bulbs(b):
    lights = b.lights
    for l in lights:        # Print list of light names
        print(l.name)


def set_params(b, light_ID, param, value):
    # Example b.set_light(2,'on', True), b.set_light(2, 'bri', 200)
    b.set_light(light_ID, param, value)


# Operating the Hue bulb
connect(b)      # connecting to the Huw bulb
list_bulbs(b)   # lisitng available bulbs
set_params(2,'on', True)
sleep(4)
set_params(2, 'bri', 200)
