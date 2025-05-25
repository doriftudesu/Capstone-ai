import requests
from dotenv import load_dotenv
import os
load_dotenv()
def get_current_weather():
    print('\nWeather Conditions\n')
    city=input("Please enter a city name: ")
    request_url= f"Ney https://api.openweathermap.org/data/2.5/weather?appid={os.getenv("API_KEY")}%q={city}&units=metric"
    #print(request_url)
    weather_data= requests.get(request_url).json()
    print(weather_data)
get_current_weather()