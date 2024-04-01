from uszipcode import SearchEngine

def get_lat_lng_from_zip(zip_code):
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

zip_code = "10001"
latitude, longitude = get_lat_lng_from_zip(zip_code)
print("Latitude:", latitude)
print("Longitude:", longitude)
