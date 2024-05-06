import requests
from uszipcode import SearchEngine

API_KEY = "129124b09cdff6292a9970660cd37091"

class APIImplementation:
    """
    This is the separate functionality for the API implementation
    """
    def get_lat_lng_from_zip(self, zip_code):
        """
        Get latitude and longitude from a given zip code using the uszipcode library.
        
        Args:
        - zip_code (str): The zip code for which latitude and longitude are needed.
        
        Returns:
        - tuple: A tuple containing latitude and longitude (lat, lng).
        """
        search = SearchEngine()
        result = search.by_zipcode(zip_code)
        if result:
            return result.lat, result.lng
        else:
            print("Error: Unable to retrieve data for the given zip code.")
            return None, None

    def get_weather_response(self, lat, long):
        """
        This function queries the weather API and returns the response JSON

        Args:
            lat (float): latitude value
            long (float): longitude value

        Returns:
            dictionary: JSON response from API
        """
        endpoint_url = f"https://api.openweathermap.org/data/3.0/onecall?lat={lat}&lon={long}&appid={API_KEY}&units=imperial"

        response = requests.get(endpoint_url, 100)

        if response.status_code == 200:
            print("API Response:")
            return response.json()
        else:
            print(f"Failed to retrieve data. Status code: {response.status_code}")
            return None
