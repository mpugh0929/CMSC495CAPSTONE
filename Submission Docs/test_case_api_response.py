"""
This file contains the unit tests for the zip code to lat/long library
and the API implementation
"""
import unittest
from api_implementation_test import APIImplementation

class TestAPIImplementation(unittest.TestCase):
    """
    This is the class that contains the test for the API implementation
    """
    def test_api(self):
        """
        This function checks if the API response has a value
        """
        zip_code = "10001"
        api_imp = APIImplementation()
        lat, long = api_imp.get_lat_lng_from_zip(zip_code)
        response = api_imp.get_weather_response(lat, long)
        self.assertTrue(response is not None)
        self.assertIn("current", response)

    def test_get_lat_lng_from_zip(self):
        """
        Test the library to get the lat/long values from zip code
        """
        api_impl = APIImplementation()
        zip_code = "10001"
        lat, lng = api_impl.get_lat_lng_from_zip(zip_code)
        self.assertIsNotNone(lat)
        self.assertIsNotNone(lng)

if __name__ == '__main__':
    unittest.main()
